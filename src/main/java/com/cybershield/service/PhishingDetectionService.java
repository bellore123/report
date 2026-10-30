package com.cybershield.service;

import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.regex.Pattern;

/**
 * PhishingDetectionService — NEW MODULE.
 *
 * Heuristic phishing / scam link scanner, built directly into CyberShield
 * Nexus (rather than as a separate app) so it shares the same login,
 * database, and deployment as the rest of the SOC platform.
 *
 * Fully offline — no external threat-intel API calls. Every check is a
 * well-documented phishing red flag; each contributes weighted points to
 * a 0-100 risk score.
 */
@Service
public class PhishingDetectionService {

    private static final Set<String> KNOWN_SHORTENERS = Set.of(
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
            "adf.ly", "cutt.ly", "shorte.st", "bl.ink", "rebrand.ly", "s.id",
            "tiny.cc", "rb.gy", "shorturl.at"
    );

    private static final Set<String> SUSPICIOUS_TLDS = Set.of(
            ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click",
            ".zip", ".mov", ".loan", ".win", ".men", ".review", ".date", ".stream",
            ".icu", ".rest"
    );

    private static final List<String> SUSPICIOUS_KEYWORDS = List.of(
            "login", "signin", "verify", "secure", "account", "update", "confirm",
            "banking", "password", "wallet", "unlock", "suspended", "billing",
            "invoice", "refund", "reward", "gift", "prize", "urgent", "limited"
    );

    private static final List<String> WATCHED_BRANDS = List.of(
            "paypal", "google", "microsoft", "apple", "amazon", "facebook",
            "instagram", "netflix", "bankofamerica", "chase", "wellsfargo",
            "whatsapp", "linkedin", "icicibank", "hdfcbank", "sbi", "irctc",
            "flipkart", "outlook", "gmail"
    );

    private static final Pattern IP_REGEX = Pattern.compile(
            "^(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$"
    );

    public record Finding(String check, int points, String detail) {}

    public record AnalysisResult(String url, int score, String verdict, List<Finding> findings) {}

    private static int levenshtein(String a, String b) {
        if (a.equals(b)) return 0;
        if (a.isEmpty()) return b.length();
        if (b.isEmpty()) return a.length();

        int[] prevRow = new int[b.length() + 1];
        for (int j = 0; j <= b.length(); j++) prevRow[j] = j;

        for (int i = 1; i <= a.length(); i++) {
            int[] currRow = new int[b.length() + 1];
            currRow[0] = i;
            for (int j = 1; j <= b.length(); j++) {
                int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
                currRow[j] = Math.min(Math.min(
                        prevRow[j] + 1,
                        currRow[j - 1] + 1),
                        prevRow[j - 1] + cost);
            }
            prevRow = currRow;
        }
        return prevRow[b.length()];
    }

    public AnalysisResult analyze(String rawUrl) {
        List<Finding> findings = new ArrayList<>();
        int[] score = {0}; // mutable holder for use in lambda-free helper

        String url = rawUrl == null ? "" : rawUrl.trim();
        if (url.isEmpty()) {
            return new AnalysisResult(rawUrl, 0, "Safe", findings);
        }

        String parseTarget = url.contains("://") ? url : "http://" + url;
        URI uri;
        String hostname = "";
        String scheme = "";
        String path = "";
        int port = -1;
        try {
            uri = new URI(parseTarget);
            hostname = uri.getHost() != null ? uri.getHost().toLowerCase() : "";
            scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase() : "";
            path = (uri.getRawPath() != null ? uri.getRawPath() : "") +
                    (uri.getRawQuery() != null ? "?" + uri.getRawQuery() : "");
            port = uri.getPort();
        } catch (URISyntaxException e) {
            findings.add(new Finding("Malformed URL", 20, "Could not parse the URL structure at all."));
        }

        // 1. IP address as hostname
        if (!hostname.isEmpty() && IP_REGEX.matcher(hostname).matches()) {
            score[0] += 25;
            findings.add(new Finding("IP address as hostname", 25,
                    "The link uses a raw IP address instead of a domain name — a very common phishing/malware-hosting pattern."));
        }

        // 2. '@' symbol in URL
        if (url.contains("@")) {
            score[0] += 25;
            findings.add(new Finding("'@' symbol in URL", 25,
                    "Everything before '@' is ignored by browsers, so attackers hide the real destination after it."));
        }

        // 3. URL length
        if (url.length() > 100) {
            score[0] += 10;
            findings.add(new Finding("Unusually long URL", 10,
                    "URL is " + url.length() + " characters — long URLs are often used to hide the real domain."));
        } else if (url.length() > 75) {
            score[0] += 5;
            findings.add(new Finding("Long URL", 5, "URL is " + url.length() + " characters, longer than typical."));
        }

        // 4. Excessive subdomains
        if (!hostname.isEmpty()) {
            int labelCount = (int) hostname.chars().filter(c -> c == '.').count();
            if (labelCount >= 4) {
                score[0] += 20;
                findings.add(new Finding("Excessive subdomains", 20,
                        "Hostname has " + labelCount + " dot-separated labels — often used to bury a fake brand name."));
            } else if (labelCount == 3) {
                score[0] += 10;
                findings.add(new Finding("Multiple subdomains", 10,
                        "Hostname has " + labelCount + " dot-separated labels, more than usual."));
            }
        }

        // 5. Known URL shortener
        if (KNOWN_SHORTENERS.contains(hostname)) {
            score[0] += 15;
            findings.add(new Finding("URL shortener", 15,
                    "'" + hostname + "' is a link-shortening service — the real destination is hidden until you click."));
        }

        // 6. Suspicious TLD
        for (String tld : SUSPICIOUS_TLDS) {
            if (hostname.endsWith(tld)) {
                score[0] += 15;
                findings.add(new Finding("Suspicious top-level domain", 15,
                        "'" + tld + "' is a low-cost TLD frequently abused for throwaway phishing domains."));
                break;
            }
        }

        // 7. Punycode
        if (hostname.contains("xn--")) {
            score[0] += 20;
            findings.add(new Finding("Punycode domain", 20,
                    "Domain uses punycode encoding (xn--) — can be used to spoof look-alike characters from other alphabets."));
        }

        // 8. Hyphens
        long hyphenCount = hostname.chars().filter(c -> c == '-').count();
        if (hyphenCount >= 2) {
            score[0] += 15;
            findings.add(new Finding("Multiple hyphens in domain", 15,
                    "Domain contains " + hyphenCount + " hyphens — a common trick to mimic an official brand subdomain."));
        } else if (hyphenCount == 1) {
            score[0] += 5;
            findings.add(new Finding("Hyphen in domain", 5, "Domain contains a hyphen."));
        }

        // 9. No HTTPS
        if (!scheme.equals("https")) {
            score[0] += 10;
            findings.add(new Finding("Not using HTTPS", 10,
                    "Connection is not encrypted — legitimate login/payment pages almost always use HTTPS."));
        }

        // 10. Suspicious lure keywords
        String lowerPath = path.toLowerCase();
        List<String> hitKeywords = new ArrayList<>();
        for (String kw : SUSPICIOUS_KEYWORDS) {
            if (lowerPath.contains(kw)) hitKeywords.add(kw);
        }
        if (!hitKeywords.isEmpty()) {
            int pts = Math.min(20, 5 * hitKeywords.size());
            score[0] += pts;
            findings.add(new Finding("Phishing lure keywords in URL", pts,
                    "Found: " + String.join(", ", hitKeywords.subList(0, Math.min(6, hitKeywords.size())))));
        }

        // 11. Non-standard port
        if (port != -1 && port != 80 && port != 443) {
            score[0] += 10;
            findings.add(new Finding("Non-standard port", 10,
                    "URL explicitly uses port " + port + ", unusual for normal browsing."));
        }

        // 12. Typosquatting / brand impersonation
        if (!hostname.isEmpty()) {
            String[] parts = hostname.split("\\.");
            String mainLabel = parts.length >= 2 ? parts[parts.length - 2] : parts[0];
            for (String brand : WATCHED_BRANDS) {
                if (mainLabel.equals(brand)) break; // exact match to real domain root
                int dist = levenshtein(mainLabel, brand);
                if (dist > 0 && dist <= 2 && mainLabel.length() >= 4) {
                    score[0] += 30;
                    findings.add(new Finding("Possible brand impersonation (typosquatting)", 30,
                            "Domain label '" + mainLabel + "' closely resembles the brand '" + brand +
                                    "' (edit distance " + dist + ") but is not an exact match."));
                    break;
                }
                if (mainLabel.contains(brand) && !mainLabel.equals(brand)) {
                    score[0] += 20;
                    findings.add(new Finding("Brand name embedded in domain", 20,
                            "Domain contains '" + brand + "' but is not the brand's real domain — likely impersonation."));
                    break;
                }
            }
        }

        int finalScore = Math.max(0, Math.min(100, score[0]));
        String verdict = finalScore >= 55 ? "Likely Phishing" : finalScore >= 25 ? "Suspicious" : "Safe";

        return new AnalysisResult(rawUrl, finalScore, verdict, findings);
    }

    public List<AnalysisResult> analyzeBatch(List<String> urls) {
        List<AnalysisResult> results = new ArrayList<>();
        for (String u : urls.subList(0, Math.min(urls.size(), 100))) {
            results.add(analyze(u));
        }
        return results;
    }
}
