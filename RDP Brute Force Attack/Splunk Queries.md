### Suspicios Number of attempts from source IP:
```SPL
source="BTLO_Bruteforce_Challenge.txt" host="BTLO" index="btlo" sourcetype="btlo_bruteforce_security_logs"
| stats count by src_ip
| where count > 10
```

### Port Range:
```SPL
source="BTLO_Bruteforce_Challenge.txt" host="BTLO" index="btlo" sourcetype="btlo_bruteforce_security_logs"
| stats max(src_port) as HighestPort, min(src_port) as LowestPort
```

### Attack Duration:
```SPL
source="BTLO_Bruteforce_Challenge.txt" host="BTLO" index="btlo" sourcetype="btlo_bruteforce_security_logs"
| stats count min(_time) as first_attempt max(_time) as last_attempt by src_ip
| eval duration_minutes=(last_attempt-first_attempt)/60
```
