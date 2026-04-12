package threatintel

import (
	"context"
	"time"
)

// Known cryptomining pool domains.
// These are common public mining pools — presence indicates a user is either
// mining on a VPS behind our VPN or unknowingly running mining malware.
var miningPoolDomains = []string{
	// Monero pools
	"pool.supportxmr.com",
	"supportxmr.com",
	"xmr.nanopool.org",
	"nanopool.org",
	"pool.minexmr.com",
	"minexmr.com",
	"xmrpool.eu",
	"moneropool.com",
	"xmr.2miners.com",
	"xmr-eu1.nanopool.org",
	"xmr-eu2.nanopool.org",
	"xmr-us-east1.nanopool.org",
	"xmr-asia1.nanopool.org",
	"c3pool.com",
	"xmr.hashvault.pro",
	"hashvault.pro",
	"mine.c3pool.com",
	"pool.hashvault.pro",
	// Ethereum / ETC pools
	"eth.2miners.com",
	"2miners.com",
	"ethermine.org",
	"ethpool.org",
	"f2pool.com",
	"etc.2miners.com",
	"etc.ethermine.org",
	"flypool.org",
	// Multi-coin / generic
	"minergate.com",
	"pool.minergate.com",
	"nicehash.com",
	"mining.nicehash.com",
	"slushpool.com",
	"btc.com",
	"antpool.com",
	"viabtc.com",
	"poolin.com",
	"emcd.io",
	"zergpool.com",
	"prohashing.com",
	"unmineable.com",
	"rplant.xyz",
	"miningrigrentals.com",
	"kryptex.com",
	"binancepool.com",
	// Browser miner scripts / CoinHive successors
	"coinhive.com",
	"coin-hive.com",
	"authedmine.com",
	"cryptonight.net",
	"coinimp.com",
	"webmine.cz",
	"webminerpool.com",
	"cryptaloot.pro",
	"monerominer.rocks",
	"jsecoin.com",
	"coinpot.co",
}

// loadMiningPools adds known cryptomining pool domains.
func (f *FeedLoader) loadMiningPools(ctx context.Context) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	count := 0
	now := time.Now()
	for _, domain := range miningPoolDomains {
		if f.isWhitelisted(domain) {
			continue
		}
		// Always set — this is a curated list with high confidence.
		f.indicators[domain] = &ThreatIndicator{
			Indicator:   domain,
			Type:        "domain",
			ThreatType:  ThreatTypeMining,
			Source:      SourceMiningPools,
			Confidence:  90,
			Description: "Cryptomining pool",
			FirstSeen:   now,
			LastSeen:    now,
			CreatedAt:   now,
		}
		count++
	}
	return count, nil
}
