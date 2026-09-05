pub enum ICMPTypes {
    EchoReply = 0,
    DestUnreachable = 3,
    SourceQuench = 4, // Deprecated
    Redirect = 5,
    EchoRequest = 8,
    RouterAdvertisement = 9,
    RouterSolicitation = 10,
    TimeExceeded = 11,
    BadIPHeader = 12,
    Timestamp = 13,
    TimestampReply = 14,
    Traceroute = 30, // Deprecated
    ExtEchoRequest = 42,
    ExtEchoReply = 43,
}

// Quick Reference:
// https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages
pub enum DestUnreachableCodes {
    NetworkUnreachable = 0,
    HostUnreachable = 1,
    ProtocolUnreachable = 2,
    PortUnreachable = 3,
    FragmentationNeededAndDFSet = 4,
    SourceRouteFailed = 5,
    DestinationNetworkUnknown = 6,
    DestinationHostUnknown = 7,
    SourceHostIsolated = 8,
    NetworkAdministrativelyProhibited = 9,
    HostAdministrativelyProhibited = 10,
    NetworkUnreachableForTos = 11,
    HostUnreachableForTos = 12,
    CommunicationAdministrativelyProhibited = 13,
    HostPrecedenceViolation = 14,
    PrecedenceCutoff = 15,
}

pub enum RedirectCodes {
    Network = 0,
    Host = 1,
    TosAndNetwork = 2,
    TosAndHost = 3,
}

pub enum BadIPHeaderCodes {
    PointerIndicatesError = 0,
    MissingRequiredOption = 1,
    BadLength = 2,
}

pub enum ExtEchoReplyCodes {
    NoError = 0,
    MalformedQuery = 1,
    NoSuchInterface = 2,
    NoSuchTableEntry = 3,
    MultipleInterfacesSatisfyQuery = 4,
}

fn type_name(icmp_type: u8) -> &'static str {
    match icmp_type {
        0 => "Echo Reply",
        3 => "Destination Unreachable",
        4 => "Source Quench (deprecated)",
        5 => "Redirect",
        8 => "Echo Request",
        9 => "Router Advertisement",
        10 => "Router Solicitation",
        11 => "Time Exceeded",
        12 => "Parameter Problem: Bad IP Header",
        13 => "Timestamp",
        14 => "Timestamp Reply",
        30 => "Traceroute (deprecated)",
        42 => "Extended Echo Request",
        43 => "Extended Echo Reply",
        _ => "Unknown",
    }
}

fn dest_unreachable_description(code: u8) -> Option<&'static str> {
    Some(match code {
        0 => "Network unreachable error.",
        1 => "Host unreachable error.",
        2 => "Protocol unreachable error (the designated transport protocol is not supported).",
        3 => {
            "Port unreachable error (the designated protocol is unable to inform the host of the incoming message)."
        }
        4 => {
            "The datagram is too big. Packet fragmentation is required but the 'don't fragment' (DF) flag is on."
        }
        5 => "Source route failed error.",
        6 => "Destination network unknown error.",
        7 => "Destination host unknown error.",
        8 => "Source host isolated error.",
        9 => "The destination network is administratively prohibited.",
        10 => "The destination host is administratively prohibited.",
        11 => "The network is unreachable for Type Of Service.",
        12 => "The host is unreachable for Type Of Service.",
        13 => {
            "Communication administratively prohibited (administrative filtering prevents packet from being forwarded)."
        }
        14 => {
            "Host precedence violation (indicates the requested precedence is not permitted for the combination of host or network and port)."
        }
        15 => {
            "Precedence cutoff in effect (precedence of datagram is below the level set by the network administrators)."
        }
        _ => return None,
    })
}

fn redirect_description(code: u8) -> Option<&'static str> {
    Some(match code {
        0 => "Redirect for Network",
        1 => "Redirect for Host",
        2 => "Redirect for Type of Service and Network",
        3 => "Redirect for Type of Service and Host",
        _ => return None,
    })
}

fn bad_ip_header_description(code: u8) -> Option<&'static str> {
    Some(match code {
        0 => "Pointer indicates the error",
        1 => "Missing a required option",
        2 => "Bad length",
        _ => return None,
    })
}

fn ext_echo_reply_description(code: u8) -> Option<&'static str> {
    Some(match code {
        0 => "No Error",
        1 => "Malformed Query",
        2 => "No Such Interface",
        3 => "No Such Table Entry",
        4 => "Multiple Interfaces Satisfy Query",
        _ => return None,
    })
}

pub fn describe(icmp_type: u8, code: u8) -> String {
    let name = type_name(icmp_type);

    let code_description = match icmp_type {
        3 => dest_unreachable_description(code),
        5 => redirect_description(code),
        12 => bad_ip_header_description(code),
        43 => ext_echo_reply_description(code),
        _ => None,
    };

    match code_description {
        Some(description) => format!("{}: {}", name, description),
        None => name.to_string(),
    }
}
