### `Overview`

- Before racing, the tool fetches the target up to three times and records its current state. Two outcomes change your plans:

- The URL already classifies as live. Reported, and the tool exits 0. Maybe the file from your last run survived.
- The ***--exclude marker doesn't appear in the baseline at all***.
- The tool refuses to start: a marker that never matched will never disappear, so the race can't be won with it. Fix the marker or override with ***--force.***

### `Usage`

- Start the tool first, then fire your upload. The baseline takes a moment, then polling runs continuously.

        python3 uploadracer.py --url http://test.com/uploads/shell.php --exclude "Not Found"

- When the confirmation streak completes you get the status code, byte count, content type, elapsed time, poll count, and the response body, escape-sanitized and truncated at --max-display.

- Milliseconds-wide deletion window:

        python3 uploadracer.py --url http://test.com/up/x.aspx --exclude "404" \  --confirmations 1 --timeout 3 --connect-timeout 2

- Webshell with a known signature, against a self-signed lab, through Burp:

        python3 uploadracer.py --url https://test.com/uploads/cmd.php \  --exclude "Not Found" --include "<?php" \  --proxy http://127.0.0.1:8080 --insecure

- Upload endpoint that only serves localhost:

        python3 uploadracer.py --url http://test.com/uploads/x.php --exclude "Not Found" \  --header "X-Forwarded-For: 127.0.0.1"

- Soft 404 apps that answer everything with status 200:

        pass --success-status 0 so the status layer accepts any 2xx, and let --include carry detection with a signature that exists only in the live file.

        Flag	Default	Purpose
        
        --url	required	Public URL of the uploaded file. http/https only.
        --exclude	required	Substring present while the file is absent. Must be non empty.
        --include	off	Substring that must appear once the file is live. Strongest false positive control.
        --success-status	200	Status counted as live. 0 accepts any 2xx.
        --confirmations	2	Consecutive passing polls required to declare victory.
        --timeout	10	Read timeout per request, seconds.
        --connect-timeout	5	Connect timeout per request, seconds.
        --delay	0	Pause between polls. 0 races at full speed.
        --max-attempts	0	Hard poll cap. 0 means unlimited.
        --net-fail-limit	10	Consecutive transport errors before abort.
        --error-delay	1	Backoff after a transport error.
        --max-body-bytes	1048576	Bytes inspected per response. Detection runs on this portion only.
        --max-display	4096	Characters of the final body printed. 0 for everything.
        --user-agent	UploadRacer/2.0.0	UA header.
        --header	none	Extra request header, repeatable. Validated against RFC 7230 token rules.
        --proxy	off	Proxy URL, applied to http and https.
        --insecure	off	Disable TLS verification. Labs only.
        --no-redirects	off	Treat redirects as "not live yet" instead of following them.
        --force	off	Race even when --exclude didn't match the baseline.
        --version		Print the version.
