//! The objects the agent reads.

use crate::ber::Oid;

macro_rules! oids {
    ($($name:ident = $s:expr;)*) => { $(pub fn $name() -> Oid { Oid::of($s) })* };
}

oids! {
    // SNMPv2-MIB system group.
    sys_descr = "1.3.6.1.2.1.1.1.0";
    sys_object_id = "1.3.6.1.2.1.1.2.0";
    sys_uptime = "1.3.6.1.2.1.1.3.0";
    sys_contact = "1.3.6.1.2.1.1.4.0";
    sys_name = "1.3.6.1.2.1.1.5.0";
    sys_location = "1.3.6.1.2.1.1.6.0";
    // IF-MIB ifTable and ifXTable columns.
    if_descr = "1.3.6.1.2.1.2.2.1.2";
    if_type = "1.3.6.1.2.1.2.2.1.3";
    if_speed = "1.3.6.1.2.1.2.2.1.5";
    if_admin_status = "1.3.6.1.2.1.2.2.1.7";
    if_oper_status = "1.3.6.1.2.1.2.2.1.8";
    if_in_octets = "1.3.6.1.2.1.2.2.1.10";
    if_in_discards = "1.3.6.1.2.1.2.2.1.13";
    if_in_errors = "1.3.6.1.2.1.2.2.1.14";
    if_out_octets = "1.3.6.1.2.1.2.2.1.16";
    if_out_discards = "1.3.6.1.2.1.2.2.1.19";
    if_out_errors = "1.3.6.1.2.1.2.2.1.20";
    if_name = "1.3.6.1.2.1.31.1.1.1.1";
    if_hc_in_octets = "1.3.6.1.2.1.31.1.1.1.6";
    if_hc_out_octets = "1.3.6.1.2.1.31.1.1.1.10";
    if_high_speed = "1.3.6.1.2.1.31.1.1.1.15";
    if_alias = "1.3.6.1.2.1.31.1.1.1.18";
    // HOST-RESOURCES-MIB.
    hr_processor_load = "1.3.6.1.2.1.25.3.3.1.2";
    hr_storage_type = "1.3.6.1.2.1.25.2.3.1.2";
    hr_storage_descr = "1.3.6.1.2.1.25.2.3.1.3";
    hr_storage_units = "1.3.6.1.2.1.25.2.3.1.4";
    hr_storage_size = "1.3.6.1.2.1.25.2.3.1.5";
    hr_storage_used = "1.3.6.1.2.1.25.2.3.1.6";
    hr_storage_ram = "1.3.6.1.2.1.25.2.1.2";
    hr_storage_fixed_disk = "1.3.6.1.2.1.25.2.1.4";
    // Printer-MIB prtMarkerSuppliesTable.
    prt_supply_class = "1.3.6.1.2.1.43.11.1.1.4";
    prt_supply_type = "1.3.6.1.2.1.43.11.1.1.5";
    prt_supply_description = "1.3.6.1.2.1.43.11.1.1.6";
    prt_supply_unit = "1.3.6.1.2.1.43.11.1.1.7";
    prt_supply_max = "1.3.6.1.2.1.43.11.1.1.8";
    prt_supply_level = "1.3.6.1.2.1.43.11.1.1.9";
    // UCD-SNMP-MIB (net-snmp, many firewalls and NAS boxes): percent of CPU time idle, and memory in KB.
    ucd_cpu_idle = "1.3.6.1.4.1.2021.11.11.0";
    ucd_mem_total_real = "1.3.6.1.4.1.2021.4.5.0";
    ucd_mem_avail_real = "1.3.6.1.4.1.2021.4.6.0";
    // The v3 reports.
    usm_unsupported_sec_levels = "1.3.6.1.6.3.15.1.1.1.0";
    usm_not_in_time_windows = "1.3.6.1.6.3.15.1.1.2.0";
    usm_unknown_user_names = "1.3.6.1.6.3.15.1.1.3.0";
    usm_unknown_engine_ids = "1.3.6.1.6.3.15.1.1.4.0";
    usm_wrong_digests = "1.3.6.1.6.3.15.1.1.5.0";
    usm_decryption_errors = "1.3.6.1.6.3.15.1.1.6.0";
}
