package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// This program demonstrates how email spoofing works at the SMTP protocol level.
//
// SECURITY IMPLICATIONS:
// 1. SMTP Protocol Weakness: The base SMTP protocol (RFC 5321) does not inherently verify
//    that the sender is authorized to use the address in the 'MAIL FROM' command or the 'From' header.
// 2. Envelope vs. Header:
//    - Envelope Sender (MAIL FROM): Used for routing and bounce messages (Return-Path).
//      This is what SPF checks.
//    - Header Sender (From:): What the user sees in their email client.
//      This can be anything, independent of the envelope sender.
// 3. Spoofing: By connecting directly to an MX server (mimicking a relay), we can specify
//    arbitrary values for both valid envelope senders (to pass some checks) and fake headers.
//
// MITIGATIONS:
// - SPF (Sender Policy Framework): Checks if the connecting IP is authorized for the MAIL FROM domain.
// - DKIM (DomainKeys Identified Mail): Cryptographically signs the message body and headers.
// - DMARC (Domain-based Message Authentication, Reporting, and Conformance): Enforces SPF/DKIM
//   policies and checks for alignment between the From header and the authenticated domain.

func main() {
	// 1. Parse Command Line Arguments
	// We allow the user to control the sender address to demonstrate spoofing.
	sender := flag.String("sender", "", "The email address to spoof (e.g., boss@company.com)")
	recipient := flag.String("recipient", "", "The target email address (YOU)")
	subject := flag.String("subject", "Urgent Update", "Email subject")
	body := flag.String("body", "Please update your password immediately.", "Email body")

	// We also allow overriding the server for testing/debugging (e.g., localhost:25)
	// But default behavior is to look up the MX record.
	server := flag.String("server", "", "Override MX lookup and send to specific server:port")

	flag.Parse()

	if *sender == "" || *recipient == "" {
		fmt.Println("Usage: spoofer -sender <spoofed_email> -recipient <your_email> [options]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	targetServer := *server

	// 2. Perform MX Record Lookup (if server not specified)
	// Real MTAs (Mail Transfer Agents) look up the MX record of the recipient's domain
	// to know where to deliver the email. We replicate this behavior.
	if targetServer == "" {
		domainParts := strings.Split(*recipient, "@")
		if len(domainParts) != 2 {
			log.Fatalf("Invalid recipient email format: %s", *recipient)
		}
		domain := domainParts[1]

		fmt.Printf("[*] Looking up MX records for domain: %s...\n", domain)
		mxRecords, err := net.LookupMX(domain)
		if err != nil {
			log.Fatalf("MX lookup failed: %v", err)
		}

		if len(mxRecords) == 0 {
			log.Fatalf("No MX records found for %s", domain)
		}

		// Pick the highest priority MX record (lowest Pref value)
		// net.LookupMX usually sorts by preference, but just in case, we take the first one.
		targetServer = mxRecords[0].Host
		// Remove trailing dot if present
		targetServer = strings.TrimSuffix(targetServer, ".")

		if targetServer == "" || targetServer == "." {
			fmt.Printf("\n[!] ERROR: The domain '%s' has a Null MX record (host='%s').\n", domain, targetServer)
			fmt.Println("    This means the domain explicitly does not accept email.")
			fmt.Println("    Please use a real email address for the recipient (e.g., your own personal email).")
			os.Exit(1)
		}

		fmt.Printf("[+] Found MX server: %s (Pref: %d)\n", targetServer, mxRecords[0].Pref)
	} else {
		fmt.Printf("[*] Using manually specified server: %s\n", targetServer)
	}

	// check if swaks is installed
	swaksCmd := "swaks"
	_, err := exec.LookPath("swaks")
	if err != nil {
		// fallback: check if swaks.bat exists in the current directory or executable directory
		// For simplicity, we check current directory first
		if _, err := os.Stat("swaks.bat"); err == nil {
			swaksCmd = ".\\swaks.bat"
			fmt.Println("[*] Using local swaks.bat wrapper.")
		} else {
			fmt.Println("\n[!] ERROR: 'swaks' tool not found in PATH nor 'swaks.bat' in current directory.")
			fmt.Println("    This program acts as a wrapper around the 'swaks' tool.")
			fmt.Println("    Please install swaks to proceed.")
			fmt.Println("    - Windows: You might need to install Perl and use 'cpan' or download swaks script.")
			fmt.Println("    - Linux/Mac: 'apt install swaks' or 'brew install swaks'")
			os.Exit(1)
		}
	}

	// 3. Construct Swaks Command
	// We use swaks to handle the raw SMTP conversation.
	// We map our Go variables to swaks flags.
	//
	// --to: The recipient
	// --from: The envelope sender (MAIL FROM). We use the spoofed address here for simplicity,
	//         but sophisticated spoofing might use a legitimate owned domain here to pass SPF,
	//         while spoofing the header 'From'.
	// --h-From: The header 'From'. This is what is displayed to the user.
	// --server: The target MX server we found.
	// --port: 25 (Standard SMTP port for inter-server communication).

	fmt.Printf("[*] Preparing to send email via SMTP to %s:25...\n", targetServer)
	fmt.Printf("    Sender: %s\n", *sender)
	fmt.Printf("    Recipient: %s\n", *recipient)

	cmd := exec.Command(swaksCmd,
		"--to", *recipient,
		"--from", *sender, // Envelope Sender
		"--h-From", *sender, // Header Sender (matching envelope for this basic demo)
		"--h-Subject", *subject,
		"--body", *body,
		"--server", targetServer,
		"--port", "25",
		"--timeout", "30s",
	)

	// We'll pipe the output to our stdout so the user can see the SMTP transaction
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// 4. Execute Command
	// Note: Connectivity to port 25 is often blocked by residential ISPs to prevent spam.
	// If this times out or fails to connect, that is likely the reason.
	fmt.Println("\n[>] Executing raw SMTP transaction...")
	fmt.Println("---------------------------------------------------")

	start := time.Now()
	err = cmd.Run()
	duration := time.Since(start)

	fmt.Println("---------------------------------------------------")

	if err != nil {
		fmt.Printf("\n[!] Sending failed: %v\n", err)
		fmt.Println("\n[?] Troubleshooting:")
		fmt.Println("    1. Port 25 Blocked: Most ISPs block outgoing port 25.")
		fmt.Println("       Try using a VPN or a cloud server (AWS, DigitalOcean, etc.) if local.")
		fmt.Println("    2. IP Reputation: The receiving server might have immediately rejected your IP.")
		fmt.Println("    3. Invalid MX: The MX record might be unreachable.")
		os.Exit(1)
	}

	fmt.Printf("\n[+] Email sent successfully (or accepted by server) in %v.\n", duration)
	fmt.Println("[*] Check your spam folder! Without SPF/DKIM, this will likely be flagged.")
}
