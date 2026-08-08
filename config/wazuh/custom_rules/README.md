# Custom Wazuh Detection Rules

Three rule files implementing the detection scenarios described in the
paper's evaluation (Section 5): SSH brute-force, general authentication
failures, and unauthorized access / remote-access anomalies.

## Installation

1. Copy the desired `.xml` file(s) into your Wazuh manager's rules
   directory, typically:
   ```
   /var/ossec/etc/rules/
   ```
2. Reference the file in `ossec.conf` under `<ruleset><rule_files>`:
   ```xml
   <ruleset>
     <rule_files>
       <rule_file>ssh_bruteforce.xml</rule_file>
       <rule_file>auth_failures.xml</rule_file>
       <rule_file>unauthorized_access.xml</rule_file>
     </rule_files>
   </ruleset>
   ```
3. Restart the Wazuh manager:
   ```
   systemctl restart wazuh-manager
   ```
4. Validate the rules loaded without errors:
   ```
   /var/ossec/bin/wazuh-logtest
   ```

## Rule ID allocation

All custom rules use IDs in the `100000-100099` range, following Wazuh's
convention that IDs below 100000 are reserved for the default ruleset.
If you add further custom rules, continue from `100033` to avoid
collisions with the rules in this repository.

## Tuning

The frequency/timeframe thresholds in these rules (e.g., 8 attempts in
120 seconds for SSH brute-force) reflect the detection configuration
used in the paper's evaluation. Adjust them to match your own
environment's traffic patterns as needed.
