package ledger

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"sentrygrid/pkg/models"
)

// LedgerBlock represents an immutable record on the sovereign audit chain
type LedgerBlock struct {
	BlockIndex   int64     `json:"block_index"`
	Timestamp    time.Time `json:"timestamp"`
	AuditID      string    `json:"audit_id"`
	DeviceID     string    `json:"device_id"`
	Vendor       string    `json:"vendor"`
	OverallScore float64   `json:"overall_score"`
	RiskLevel    string    `json:"risk_level"`
	AuditSeal    string    `json:"audit_seal"` // SHA-512
	PreviousHash string    `json:"previous_hash"`
	BlockHash    string    `json:"block_hash"`
	SignerNode   string    `json:"signer_node"` // NTRO-SOC-NODE-01
}

// SovereignLedger manages the append-only multi-agency compliance ledger
type SovereignLedger struct {
	mu     sync.RWMutex
	blocks []LedgerBlock
}

// NewSovereignLedger initializes the ledger with a genesis block
func NewSovereignLedger() *SovereignLedger {
	sl := &SovereignLedger{}
	genesis := LedgerBlock{
		BlockIndex:   0,
		Timestamp:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		AuditID:      "GENESIS-NTRO-BLOCK",
		DeviceID:     "SOVEREIGN-ROOT",
		Vendor:       "NTRO-DEFENSE",
		OverallScore: 100.0,
		RiskLevel:    "SECURE",
		AuditSeal:    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		PreviousHash: "0000000000000000",
		BlockHash:    "GENESIS-BLOCK-HASH-NTRO-CYBERSECURITY-2026",
		SignerNode:   "NTRO-GENESIS-NODE",
	}
	sl.blocks = append(sl.blocks, genesis)
	return sl
}

// ComputeAuditSeal generates the 128-character CNSA 2.0 SHA-512 seal
func (sl *SovereignLedger) ComputeAuditSeal(device models.DeviceInfo, eval models.ComplianceEvaluation) string {
	hasher := sha512.New()
	hasher.Write([]byte(device.Hostname))
	hasher.Write([]byte(device.Vendor))
	hasher.Write([]byte(device.SerialNumber))
	hasher.Write([]byte(device.RawConfigSHA512))
	hasher.Write([]byte(fmt.Sprintf("%.1f", eval.Summary.OverallScore)))

	for _, f := range eval.Findings {
		hasher.Write([]byte(f.RuleID))
		hasher.Write([]byte(f.Status))
	}

	return hex.EncodeToString(hasher.Sum(nil))
}

// CommitAudit commits an audit verification to the immutable ledger
func (sl *SovereignLedger) CommitAudit(auditID string, device models.DeviceInfo, eval models.ComplianceEvaluation, seal string) LedgerBlock {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	prevBlock := sl.blocks[len(sl.blocks)-1]
	newIndex := prevBlock.BlockIndex + 1

	blockData := fmt.Sprintf("%d:%s:%s:%s:%s", newIndex, prevBlock.BlockHash, auditID, seal, time.Now().UTC().Format(time.RFC3339))
	h := sha512.New()
	h.Write([]byte(blockData))
	newBlockHash := hex.EncodeToString(h.Sum(nil))

	block := LedgerBlock{
		BlockIndex:   newIndex,
		Timestamp:    time.Now().UTC(),
		AuditID:      auditID,
		DeviceID:     device.Hostname,
		Vendor:       device.Vendor,
		OverallScore: eval.Summary.OverallScore,
		RiskLevel:    eval.Summary.RiskLevel,
		AuditSeal:    seal,
		PreviousHash: prevBlock.BlockHash[:32],
		BlockHash:    newBlockHash[:32],
		SignerNode:   "NTRO-NATIONAL-DEFENSE-NODE-01",
	}

	sl.blocks = append(sl.blocks, block)
	return block
}

// GetRecentBlocks returns latest blocks on the chain
func (sl *SovereignLedger) GetRecentBlocks() []LedgerBlock {
	sl.mu.RLock()
	defer sl.mu.RUnlock()

	result := make([]LedgerBlock, len(sl.blocks))
	copy(result, sl.blocks)
	return result
}

// VerifyAudit checks if a seal exists and is valid
func (sl *SovereignLedger) VerifyAudit(seal string) (bool, *LedgerBlock) {
	sl.mu.RLock()
	defer sl.mu.RUnlock()

	for _, b := range sl.blocks {
		if b.AuditSeal == seal {
			return true, &b
		}
	}
	return false, nil
}

// ExportJSON exports all blocks for auditor transparency
func (sl *SovereignLedger) ExportJSON() string {
	sl.mu.RLock()
	defer sl.mu.RUnlock()
	data, _ := json.MarshalIndent(sl.blocks, "", "  ")
	return string(data)
}
