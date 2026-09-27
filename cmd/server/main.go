package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"sentrygrid/pkg/compliance"
	"sentrygrid/pkg/fingerprint"
	"sentrygrid/pkg/laya"
	"sentrygrid/pkg/ledger"
	"sentrygrid/pkg/models"
	"sentrygrid/pkg/samples"
)

type Server struct {
	layaEngine  *laya.DecisionEngine
	evaluator   *compliance.ComplianceEvaluator
	ledger      *ledger.SovereignLedger
	sampleList  []samples.SampleConfig
	templates   *template.Template
	lastAudit   *models.AuditResult
}

type PageData struct {
	LedgerHeight     int64
	LedgerBlocks     []ledger.LedgerBlock
	ActiveHeuristics []*models.DynamicHeuristicRule
	Samples          []samples.SampleConfig
	InitialAudit     *models.AuditResult
	UnmappedLines    []models.UnmappedLine
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &Server{
		layaEngine: laya.NewDecisionEngine("heuristics_cache.json"),
		evaluator:  compliance.NewComplianceEvaluator(),
		ledger:     ledger.NewSovereignLedger(),
		sampleList: samples.GetSampleConfigs(),
	}

	// Parse templates
	tmpl, err := template.ParseFiles("templates/index.html", "templates/partials/audit_results_partial.html")
	if err != nil {
		log.Fatalf("Template parse error: %v", err)
	}
	srv.templates = tmpl

	// Perform initial baseline audit on first sample
	firstSample := srv.sampleList[0]
	device := fingerprint.DetectDevice(firstSample.Content)
	eval, unmapped := srv.evaluator.EvaluateFull(firstSample.Content, device.Vendor, srv.layaEngine)
	seal := srv.ledger.ComputeAuditSeal(device, eval)
	block := srv.ledger.CommitAudit("AUD-INIT-001", device, eval, seal)

	srv.lastAudit = &models.AuditResult{
		Metadata: models.AuditMetadata{
			AuditID:           "AUD-INIT-001",
			Timestamp:         time.Now().UTC(),
			SchemaVersion:     "1.0.0",
			HashAlgorithm:     "SHA-512",
			CryptographicSeal: seal,
			LedgerBlockIndex:  block.BlockIndex,
		},
		DeviceInfo:           device,
		UnmappedLines:        unmapped,
		ComplianceEvaluation: eval,
	}

	// Routes
	http.HandleFunc("/", srv.handleIndex)
	http.HandleFunc("/api/audit", srv.handleAudit)
	http.HandleFunc("/api/ai/crystallize", srv.handleCrystallize)
	http.HandleFunc("/api/ledger/blocks", srv.handleLedgerBlocks)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	fmt.Printf("\n=======================================================\n")
	fmt.Printf(" SENTRY-GRID SOVEREIGN COMPLIANCE AUDITOR (SIH26155)\n")
	fmt.Printf(" National Technical Research Organisation (NTRO)\n")
	fmt.Printf("=======================================================\n")
	fmt.Printf(" Server listening at: http://localhost:%s\n", port)
	fmt.Printf(" Laya System-1 Model: ACTIVE (<10ms logit routing)\n")
	fmt.Printf(" Cryptographic Seal:  CNSA 2.0 SHA-512\n")
	fmt.Printf(" Frameworks:          CIS, DISA STIG, NIST SP 800-53, ISO 27001\n")
	fmt.Printf("=======================================================\n\n")

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	recentBlocks := s.ledger.GetRecentBlocks()
	ledgerHeight := int64(0)
	if len(recentBlocks) > 0 {
		ledgerHeight = recentBlocks[len(recentBlocks)-1].BlockIndex
	}

	data := PageData{
		LedgerHeight:     ledgerHeight,
		LedgerBlocks:     recentBlocks,
		ActiveHeuristics: s.layaEngine.GetActiveHeuristics(),
		Samples:          s.sampleList,
		InitialAudit:     s.lastAudit,
		UnmappedLines:    s.lastAudit.UnmappedLines,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, "index.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	cfgText := r.FormValue("config_text")
	if cfgText == "" {
		cfgText = s.sampleList[0].Content
	}

	// 1. Hardware and OS Fingerprint
	device := fingerprint.DetectDevice(cfgText)

	// 2. Full Multi-Framework Evaluation + Laya Decision Routing
	eval, unmapped := s.evaluator.EvaluateFull(cfgText, device.Vendor, s.layaEngine)

	// 3. Compute CNSA 2.0 SHA-512 Seal
	seal := s.ledger.ComputeAuditSeal(device, eval)

	// 4. Commit to Sovereign Immutable Ledger
	auditID := fmt.Sprintf("AUD-%d", time.Now().Unix())
	block := s.ledger.CommitAudit(auditID, device, eval, seal)

	auditResult := &models.AuditResult{
		Metadata: models.AuditMetadata{
			AuditID:           auditID,
			Timestamp:         time.Now().UTC(),
			SchemaVersion:     "1.0.0",
			HashAlgorithm:     "SHA-512",
			CryptographicSeal: seal,
			LedgerBlockIndex:  block.BlockIndex,
		},
		DeviceInfo:           device,
		UnmappedLines:        unmapped,
		ComplianceEvaluation: eval,
	}
	s.lastAudit = auditResult

	// Render HTMX partial
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, "audit_results_partial", auditResult); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleCrystallize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	rawLine := r.FormValue("raw_line")
	targetCategory := r.FormValue("target_category")
	assignedVal := r.FormValue("assigned_value")
	vendorScope := r.FormValue("vendor_scope")

	rule, err := s.layaEngine.CrystallizeRule(rawLine, targetCategory, assignedVal, vendorScope)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
		<div class="mt-4 p-3 bg-emerald-950/80 border border-emerald-500/40 rounded-lg text-xs text-emerald-300 flex items-center justify-between animate-fade-in">
			<div class="flex items-center gap-2">
				<span class="text-emerald-400 font-bold">✓ Rule Crystallized!</span>
				<span>Learned: <code class="bg-black/40 px-1.5 py-0.5 rounded text-sky-300 font-mono">%s</code> mapped to <strong class="text-white">%s</strong></span>
			</div>
			<span class="text-[10px] text-slate-400 font-mono">Rule ID: %s (Active with Zero Restart)</span>
		</div>
	`, rule.PatternRegex, rule.TargetAttribute, rule.RuleID)
}

func (s *Server) handleLedgerBlocks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(s.ledger.ExportJSON()))
}
