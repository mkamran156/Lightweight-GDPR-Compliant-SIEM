<!--
  Custom Wazuh rule: SSH brute-force detection.

  Referenced in Section 4.1 ("customized security rule implementation
  for authentication failure detection and brute force attacks") and
  used to generate the simulated attack scenarios described in
  Section 5.2 ("failed SSH authentication attempts, brute-force login
  attempts").

  Rule IDs 100000-120000 are reserved for local/custom rules per Wazuh
  convention, avoiding collisions with the default ruleset. Place this
  file in /var/ossec/etc/rules/local_rules.xml or a dedicated file
  referenced from ossec.conf's <rule_files> section.
-->
<group name="ssh_bruteforce,authentication_failed,">

  <!-- Base rule: a single failed SSH login attempt. -->
  <rule id="100010" level="5">
    <if_sid>5716</if_sid>
    <description>SSHD: authentication failed.</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,gdpr_IV_35.7.d,</group>
  </rule>

  <!--
    Frequency rule: N failed attempts from the same source within a
    short window escalates to a brute-force alert.
  -->
  <rule id="100011" level="10" frequency="8" timeframe="120">
    <if_matched_sid>100010</if_matched_sid>
    <same_source_ip />
    <description>SSHD: Multiple authentication failures from the same source IP (possible brute-force attack).</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>authentication_failures,pci_dss_11.4,gdpr_IV_35.7.d,</group>
  </rule>

  <!--
    Escalation: brute-force pattern followed by a successful login from
    the same source shortly after - the highest-priority variant, since
    it suggests a credential was actually compromised.
  -->
  <rule id="100012" level="12">
    <if_matched_sid>100011</if_matched_sid>
    <same_source_ip />
    <description>SSHD: Successful login following brute-force pattern from same source IP. Possible compromised account.</description>
    <mitre>
      <id>T1110</id>
      <id>T1078</id>
    </mitre>
    <group>authentication_success,gdpr_IV_35.7.d,</group>
  </rule>

</group>
