<!--
  Custom Wazuh rules: general authentication failure detection,
  covering Windows logon failures and account lockouts in addition to
  the SSH-specific rules in ssh_bruteforce.xml.

  Referenced in Section 5.4/5.5's discussion of "multiple Windows audit
  failure events" and "User account locked out (multiple login
  failures)" appearing among the dashboard's high-severity alerts.
-->
<group name="authentication_failed,windows,">

  <rule id="100020" level="6">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^4625$</field>
    <description>Windows: logon failure.</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failed,gdpr_IV_35.7.d,</group>
  </rule>

  <rule id="100021" level="10" frequency="6" timeframe="180">
    <if_matched_sid>100020</if_matched_sid>
    <same_field>win.eventdata.targetUserName</same_field>
    <description>Windows: multiple logon failures for the same user account (possible brute-force or account lockout).</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failures,gdpr_IV_35.7.d,</group>
  </rule>

  <rule id="100022" level="10">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^4740$</field>
    <description>Windows: user account locked out (multiple login failures).</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failed,account_changed,gdpr_IV_35.7.d,</group>
  </rule>

  <rule id="100023" level="9">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^4720|4722|4724|4738$</field>
    <description>Windows: user account changed (created, enabled, password reset, or modified).</description>
    <mitre>
      <id>T1136</id>
    </mitre>
    <group>account_changed,gdpr_IV_35.7.d,</group>
  </rule>

</group>
