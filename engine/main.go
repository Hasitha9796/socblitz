package main

import (
	"context"
	"log"
	"os"
	"time"
)

// socblitz-engine: a lightweight detection engine that replaces the role of the
// Wazuh manager + Filebeat/indexer path. It ingests logs (agent HTTP / syslog),
// decodes them, matches detection rules, and writes alerts straight to
// ClickHouse — no OpenSearch, no JVM.

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	var (
		chURL     = env("CLICKHOUSE_URL", "http://clickhouse:8123")
		chUser    = env("CLICKHOUSE_USER", "socblitz")
		chPass    = env("CLICKHOUSE_PASSWORD", "")
		rulesDir    = env("ENGINE_RULES_DIR", "/app/rules")
		decodersDir = env("ENGINE_DECODERS_DIR", "/app/decoders")
		sigmaDir    = env("ENGINE_SIGMA_DIR", "/app/sigma")
		parsersDir  = env("ENGINE_PARSERS_DIR", "/app/parsers")
		yaralDir    = env("ENGINE_YARAL_DIR", "/app/yaral")
		vulnFeed  = env("ENGINE_VULN_FEED", "/app/feeds/vuln-feed.json")
		httpAddr  = env("ENGINE_HTTP_ADDR", ":8090")
		syslogUDP = env("ENGINE_SYSLOG_UDP", ":514")
		syslogTCP = env("ENGINE_SYSLOG_TCP", ":514")
		enrollKey = env("AGENT_ENROLL_KEY", "")
	)

	if ds, err := LoadDecoders(decodersDir); err != nil {
		log.Printf("decoder load warning (using built-ins): %v", err)
	} else {
		activeDecoders = ds
		log.Printf("%d decoders active (from %s)", ds.Count(), decodersDir)
	}

	// Chronicle-style normalization: CBN parsers map raw logs onto the UDM.
	if ps, err := LoadParsers(parsersDir); err != nil {
		log.Printf("parser load warning (using built-ins): %v", err)
	} else {
		activeParsers = ps
		log.Printf("%d UDM parsers active (from %s)", ps.Count(), parsersDir)
	}

	rules, err := LoadRules(rulesDir)
	if err != nil {
		log.Fatalf("load rules: %v", err)
	}
	if n, err := AppendSigma(rules, sigmaDir); err != nil {
		log.Printf("sigma load warning: %v", err)
	} else if n > 0 {
		log.Printf("loaded %d Sigma rules from %s", n, sigmaDir)
	}
	log.Printf("%d legacy rules active", rules.Count())

	// Chronicle-style detection: YARA-L rules over the UDM (single-event + windowed).
	yaral, err := LoadYaraL(yaralDir)
	if err != nil {
		log.Printf("yara-l load warning (using built-ins): %v", err)
		yaral = builtinYaraL()
	}
	correlator := NewCorrelator(yaral)
	log.Printf("%d YARA-L rules active (%d windowed)", yaral.Count(), correlator.Count())

	feed, err := loadVulnFeed(vulnFeed)
	if err != nil {
		log.Printf("vuln feed warning: %v", err)
		feed = &VulnFeed{byPackage: map[string][]CVE{}}
	}

	ch := NewCHClient(chURL, chUser, chPass)
	for i := 0; ; i++ {
		if err := ch.Ping(context.Background()); err != nil {
			if i >= 30 {
				log.Fatalf("clickhouse not reachable: %v", err)
			}
			log.Printf("waiting for clickhouse (%v)...", err)
			time.Sleep(2 * time.Second)
			continue
		}
		break
	}
	log.Printf("clickhouse ready at %s", chURL)

	// Runtime parser management: persist user-defined CBN parsers in ClickHouse
	// and hot-reload them into the active set (no restart needed).
	if err := ch.EnsureParserTable(context.Background()); err != nil {
		log.Printf("parser table warning: %v", err)
	}
	parserStore := NewParserStore(activeParsers, ch)
	if n, err := parserStore.LoadCustom(context.Background()); err != nil {
		log.Printf("custom parser load warning: %v", err)
	} else if n > 0 {
		log.Printf("loaded %d custom parsers from clickhouse", n)
	}

	pipeline := make(chan RawEvent, 8192)
	go runPipeline(pipeline, rules, yaral, correlator, parserStore, ch)

	srv := NewServer(pipeline, enrollKey, ch, feed, rules, yaral, parserStore)
	go func() {
		if err := srv.StartSyslogUDP(syslogUDP); err != nil {
			log.Printf("syslog udp: %v", err)
		}
	}()
	go func() {
		if err := srv.StartSyslogTCP(syslogTCP); err != nil {
			log.Printf("syslog tcp: %v", err)
		}
	}()
	log.Fatal(srv.StartHTTP(httpAddr))
}

// runPipeline: decode -> normalize (UDM) -> match -> batch-insert. Alerts are
// flushed when the batch fills or every second, whichever comes first.
//
// Detection runs two ways over each event: the legacy JSON/Sigma rules match on
// the decoded Event, while the Chronicle-style path normalizes the event to a
// UDM record and runs YARA-L rules over it — single-event rules inline, and
// windowed (match/condition) rules through the correlator.
func runPipeline(in chan RawEvent, rules *RuleSet, yaral *YaraLSet, correlator *Correlator, parsers *ParserStore, ch *CHClient) {
	const maxBatch = 500
	batch := make([]Alert, 0, maxBatch)
	tick := time.NewTicker(1 * time.Second)
	defer tick.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		if err := ch.InsertAlerts(ctx, batch); err != nil {
			log.Printf("insert %d alerts failed: %v", len(batch), err)
		} else {
			log.Printf("inserted %d alerts", len(batch))
		}
		cancel()
		batch = batch[:0]
	}

	for {
		select {
		case raw := <-in:
			ev := decode(raw)
			udm, _ := parsers.Current().Normalize(&ev)

			alerts := rules.Eval(&ev)                       // legacy JSON/Sigma
			alerts = append(alerts, yaral.EvalSingle(udm, &ev)...) // YARA-L single-event
			alerts = append(alerts, correlator.Observe(udm, &ev)...) // YARA-L windowed
			for _, a := range alerts {
				batch = append(batch, a)
				if len(batch) >= maxBatch {
					flush()
				}
			}
		case <-tick.C:
			flush()
		}
	}
}
