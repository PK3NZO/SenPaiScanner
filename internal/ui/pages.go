package ui

// Page identifies the active screen.
type Page int

const (
	PageProviderSelect Page = iota
	PageHome
	PageQuickScanCount // count picker for Quick Scan
	PageScanConfig
	PageLiveScan
	PageResults
	PageColos
	PageLiveColos
	PageAbout
	PageScanWithConfig // xray config - URL input
	PageConfigSetup    // xray config - count/topN setup
	PageConfigPhase1   // xray config - fast connectivity scan
	PageConfigPhase2   // xray config - xray validation
)
