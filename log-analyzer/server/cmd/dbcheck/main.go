package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	db, err := sql.Open("sqlite3", "./data/analyzer.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	var c int
	db.QueryRow("SELECT COUNT(*) FROM threat_matches").Scan(&c)
	fmt.Println("threat_matches count:", c)

	var t int
	db.QueryRow("SELECT total_matches FROM threat_stats_agg WHERE id=1").Scan(&t)
	fmt.Println("total_matches in agg:", t)

	// List threat_type_stats
	rows, err := db.Query("SELECT threat_type, match_count FROM threat_type_stats ORDER BY match_count DESC LIMIT 10")
	if err != nil {
		fmt.Println("\nThreat type stats: error -", err)
	} else {
		defer rows.Close()
		fmt.Println("\nThreat type stats:")
		for rows.Next() {
			var tt string
			var mc int
			rows.Scan(&tt, &mc)
			fmt.Printf("  %s: %d\n", tt, mc)
		}
	}

	// List user_threat_stats
	rows2, err := db.Query("SELECT user_email, threat_type, match_count FROM user_threat_stats ORDER BY match_count DESC LIMIT 10")
	if err != nil {
		fmt.Println("\nUser threat stats: error -", err)
	} else {
		defer rows2.Close()
		fmt.Println("\nUser threat stats:")
		for rows2.Next() {
			var ue, tt string
			var mc int
			rows2.Scan(&ue, &tt, &mc)
			fmt.Printf("  %s [%s]: %d\n", ue, tt, mc)
		}
	}

	// Recent matches
	rows3, err := db.Query("SELECT id, user_email, threat_type, destination, matched_at FROM threat_matches ORDER BY matched_at DESC LIMIT 5")
	if err != nil {
		fmt.Println("\nRecent matches: error -", err)
	} else {
		defer rows3.Close()
		fmt.Println("\nRecent matches:")
		for rows3.Next() {
			var id int
			var ue, tt, dest, ma string
			rows3.Scan(&id, &ue, &tt, &dest, &ma)
			fmt.Printf("  #%d %s [%s] -> %s at %s\n", id, ue, tt, dest, ma)
		}
	}
}
