// Quick Reference:
// https://en.wikipedia.org/wiki/ICMPv6#Types_of_messages
pub enum ICMPv6Types {
    DestUnreachable = 1,
    PacketTooBig = 2,
    TimeExceeded = 3,
    ParameterProblem = 4,
    PrivateExperimentation1 = 100,
    PrivateExperimentation2 = 101,
    ReservedForErrorExpansion = 127,
    EchoRequest = 128,
    EchoReply = 129,
    MulticastListenerQuery = 130,
    MulticastListenerReport = 131,
    MulticastListenerDone = 132,
    RouterSolicitation = 133,
    RouterAdvertisement = 134,
    NeighborSolicitation = 135,
    NeighborAdvertisement = 136,
    RedirectMessage = 137,
    RouterRenumbering = 138,
    NodeInformationQuery = 139,
    NodeInformationResponse = 140,
    InverseNeighborDiscoverySolicitation = 141,
    InverseNeighborDiscoveryAdvertisement = 142,
    MLDv2Report = 143,
    HomeAgentAddressDiscoveryRequest = 144,
    HomeAgentAddressDiscoveryReply = 145,
    MobilePrefixSolicitation = 146,
    MobilePrefixAdvertisement = 147,
    CertificationPathSolicitation = 148,
    CertificationPathAdvertisement = 149,
    MulticastRouterAdvertisement = 151,
    MulticastRouterSolicitation = 152,
    MulticastRouterTermination = 153,
    RplControlMessage = 155,
    ExtEchoRequest = 160,
    ExtEchoReply = 161,
    PrivateExperimentation3 = 200,
    PrivateExperimentation4 = 201,
    ReservedForInformationalExpansion = 255,
}

pub enum DestUnreachableCodes {
    NoRouteToDestination = 0,
    CommunicationAdministrativelyProhibited = 1,
    BeyondScopeOfSourceAddress = 2,
    AddressUnreachable = 3,
    PortUnreachable = 4,
    SourceAddressFailedPolicy = 5,
    RejectRouteToDestination = 6,
    ErrorInSourceRoutingHeader = 7,
}

pub enum TimeExceededCodes {
    HopLimitExceededInTransit = 0,
    FragmentReassemblyTimeExceeded = 1,
}

pub enum ParameterProblemCodes {
    ErroneousHeaderField = 0,
    UnrecognizedNextHeader = 1,
    UnrecognizedIpv6Option = 2,
}

pub enum RouterRenumberingCodes {
    Command = 0,
    Result = 1,
    SequenceNumberReset = 255,
}

pub enum NodeInformationQueryCodes {
    Ipv6AddressSubject = 0,
    NameOrNoop = 1,
    Ipv4AddressSubject = 2,
}

pub enum NodeInformationResponseCodes {
    SuccessfulReply = 0,
    ResponderRefuses = 1,
    QueryTypeUnknown = 2,
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
        1 => "Destination Unreachable",
        2 => "Packet Too Big",
        3 => "Time Exceeded",
        4 => "Parameter Problem",
        100 => "Private Experimentation",
        101 => "Private Experimentation",
        127 => "Reserved for Error Expansion",
        128 => "Echo Request",
        129 => "Echo Reply",
        130 => "Multicast Listener Query",
        131 => "Multicast Listener Report",
        132 => "Multicast Listener Done",
        133 => "Router Solicitation",
        134 => "Router Advertisement",
        135 => "Neighbor Solicitation",
        136 => "Neighbor Advertisement",
        137 => "Redirect Message",
        138 => "Router Renumbering",
        139 => "ICMP Node Information Query",
        140 => "ICMP Node Information Response",
        141 => "Inverse Neighbor Discovery Solicitation",
        142 => "Inverse Neighbor Discovery Advertisement",
        143 => "MLDv2 Report",
        144 => "Home Agent Address Discovery Request",
        145 => "Home Agent Address Discovery Reply",
        146 => "Mobile Prefix Solicitation",
        147 => "Mobile Prefix Advertisement",
        148 => "Certification Path Solicitation",
        149 => "Certification Path Advertisement",
        151 => "Multicast Router Advertisement",
        152 => "Multicast Router Solicitation",
        153 => "Multicast Router Termination",
        155 => "RPL Control Message",
        160 => "Extended Echo Request",
        161 => "Extended Echo Reply",
        200 => "Private Experimentation",
        201 => "Private Experimentation",
        255 => "Reserved for Informational Expansion",
        _ => "Unknown",
    }
}

fn dest_unreachable_description(code: u8) -> Option<&'static str> {
    Some(match code {
        0 => "No route to destination.",
        1 => "Communication with destination administratively prohibited.",
        2 => "Beyond scope of source address.",
        3 => "Address unreachable.",
        4 => "Port unreachable.",
        5 => "Source address failed ingress/egress policy.",
        6 => "Reject route to destination.",
        7 => "Error in Source Routing Header.",
        _ => return None,
    })
}

fn time_exceeded_description(code: u8) -> Option<&'static str> {
    Some(match code {
        0 => "Hop limit exceeded in transit.",
        1 => "Fragment reassembly time exceeded.",
        _ => return None,
    })
}

fn parameter_problem_description(code: u8) -> Option<&'static str> {
    Some(match code {
        0 => "Erroneous header field encountered.",
        1 => "Unrecognized Next Header type encountered.",
        2 => "Unrecognized IPv6 option encountered.",
        _ => return None,
    })
}

fn router_renumbering_description(code: u8) -> Option<&'static str> {
    Some(match code {
        0 => "Router renumbering command.",
        1 => "Router renumbering result.",
        255 => "Sequence number reset.",
        _ => return None,
    })
}

fn node_information_query_description(code: u8) -> Option<&'static str> {
    Some(match code {
        0 => "The Data field contains an IPv6 address which is the subject of this query.",
        1 => "The Data field contains a name which is the subject of this query, or is empty (NOOP).",
        2 => "The Data field contains an IPv4 address which is the subject of this query.",
        _ => return None,
    })
}

fn node_information_response_description(code: u8) -> Option<&'static str> {
    Some(match code {
        0 => "A successful reply.",
        1 => "The responder refuses to supply the answer.",
        2 => "The query type of the Query is unknown to the responder.",
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
        1 => dest_unreachable_description(code),
        3 => time_exceeded_description(code),
        4 => parameter_problem_description(code),
        138 => router_renumbering_description(code),
        139 => node_information_query_description(code),
        140 => node_information_response_description(code),
        161 => ext_echo_reply_description(code),
        _ => None,
    };

    match code_description {
        Some(description) => format!("{name}: {description}"),
        None => name.to_string(),
    }
}
