// Quick Reference:
// https://en.wikipedia.org/wiki/Internet_Group_Management_Protocol
pub enum IGMPTypes {
    MembershipQuery = 0x11,
    V1MembershipReport = 0x12,
    V2MembershipReport = 0x16,
    LeaveGroup = 0x17,
    V3MembershipReport = 0x22,
}

fn type_name(igmp_type: u8) -> &'static str {
    match igmp_type {
        0x11 => "Membership Query",
        0x12 => "IGMPv1 Membership Report",
        0x16 => "IGMPv2 Membership Report",
        0x17 => "Leave Group",
        0x22 => "IGMPv3 Membership Report",
        _ => "Unknown",
    }
}

pub fn describe(igmp_type: u8) -> String {
    type_name(igmp_type).to_string()
}
