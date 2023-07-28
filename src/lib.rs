use serde_xml_rs::Error;
use serde_xml_rs;
use serde::{Deserialize, Serialize};



/// from_str Qualys Reports
pub fn from_str<I: Into<String>>(buffer: I) -> Result<Scan, Error> {
    let report: Scan = serde_xml_rs::from_reader(buffer.into().as_bytes())?;
    Ok(report)
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Scan {
    pub value: String,

    #[serde(rename = "HEADER")]
    pub headers: Vec<Header>,
    #[serde(rename = "IP")]
    pub ips: Vec<IP>
    //#[serde(rename = "ERROR")]
    //pub error: String
}



#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Header {
    #[serde(rename = "KEY")]
    keys: Vec<Key>,
    #[serde(rename = "ASSET_GROUPS")]
    asset_groups: Option<AssetGroups>,
    //#[serde(rename = "ASSET_TAG_LIST")]
    // asset_tag_list: Option<AssetTagList>,
    #[serde(rename = "OPTION_PROFILE")]
    option_profile: Option<OptionProfile>
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct AssetGroups {   
    #[serde(rename = "ASSET_GROUP")]
    pub asset_groups: Vec<AssetGroup>
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct AssetGroup {   
    #[serde(rename = "ASSET_GROUP_TITLE")]
    pub asset_group_title: String
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct OptionProfile {
    #[serde(rename = "OPTION_PROFILE_TITLE")]
    pub option_profile_title: OptionProfileTitle
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct OptionProfileTitle {
    pub option_profile_default: String,
    #[serde(rename = "$value")]
    pub option_profile_title: String
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Key {
    pub value: String,
    
    #[serde(rename = "$value")]
    pub key: String
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct IP {
    pub value: String,
    pub name: Option<String>,
    pub status: Option<String>,

    #[serde(rename = "OS")]
    pub os: Option<String>,
    #[serde(rename = "OS_CPE")]
    pub os_cpe: Option<String>,
    #[serde(rename = "NETBIOS_HOSTNAME")]   
    pub netbios_hostname: Option<String>,
    #[serde(rename = "INFOS")]
    pub infos: Option<Infos>,
    #[serde(rename = "SERVICES")]
    pub services: Option<Services>,
    #[serde(rename = "VULNS")]
    pub vulns: Option<Vulns>,
    #[serde(rename = "PRACTICES")]
    pub practices: Option<Practices>,
    #[serde(rename = "NETWORK")]
    pub network: Option<String>
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct IPv6 {
    pub value: String,
    pub name: String,
    pub status: String,
}

///////////
// TYPES //
///////////

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Infos {
    #[serde(rename = "CAT")]
    pub cats: Vec<Cat>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Vulns {
    #[serde(rename = "CAT")]
    pub cats: Vec<Cat>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Services {
    #[serde(rename = "CAT")]
    pub cats: Vec<Cat>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Practices {
    #[serde(rename = "CAT")]
    pub cats: Vec<Cat>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub enum TCat {
    #[serde(rename = "INFO")]
    Info(Info),
    #[serde(rename = "SERVICE")]
    Service(Service),
    #[serde(rename = "VULN")]
    Vuln(Vuln),
    #[serde(rename = "PRACTICE")]
    Practice(Practice)
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Cat {
    pub value: String,
    pub fqdn: Option<String>,
    pub port: Option<String>,
    pub protocol: Option<String>,
    pub misc: Option<String>,

    #[serde(rename = "$value")]
    pub tcats: Option<Vec<TCat>>,
}


// scan -> IP -> vulns -> cat -> vuln
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]  
pub struct Vuln {
    pub number: String,
    pub severity: Option<String>,
    pub cveid: Option<String>,
    pub standard_severity: Option<String>,

    #[serde(rename = "TITLE")]
    pub title: Option<String>,
    #[serde(rename = "LAST_UPDATE")]
    pub last_update: Option<String>,
    #[serde(rename = "CVSS_BASE")]
    pub cvss_base: Option<String>,
    #[serde(rename = "CVSS_TEMPORAL")]
    pub cvss_temporal: Option<String>,
    #[serde(rename = "CVSS3_BASE")]
    pub cvss3_base: Option<String>,
    #[serde(rename = "CVSS3_TEMPORAL")]
    pub cvss3_temporal: Option<String>,
    #[serde(rename = "CVSS3_VERSION")]
    pub cvss3_version: Option<String>,
    #[serde(rename = "PCI_FLAG")]
    pub pci_flag: Option<String>,
    #[serde(rename = "INSTANCE")]
    pub instance: Option<String>,
    #[serde(rename = "VENDOR_REFERENCE_LIST")]
    pub vendor_reference_list: Option<VendorReferenceList>,
    #[serde(rename = "CVE_ID_LIST")]
    pub cve_id_list: Option<CveIdList>,
    #[serde(rename = "BUGTRAQ_ID_LIST")]
    pub bugtraq_id_list: Option<BugTraqIdList>,
    #[serde(rename = "DIAGNOSIS")]
    pub diagnosis: Option<String>,
    #[serde(rename = "DIAGNOSIS_COMMENT")]
    pub diagnosis_comment: Option<String>,
    #[serde(rename = "CONSEQUENCE")]
    pub consequence: Option<String>,
    #[serde(rename = "CONSEQUENCE_COMMENT")]
    pub consequence_comment: Option<String>,
    #[serde(rename = "SOLUTION")]
    pub solution: Option<String>,
    #[serde(rename = "SOLUTION_COMMENT")]
    pub solution_comment: Option<String>,
    #[serde(rename = "COMPLIANCE")]
    pub compliance: Option<Compliance>,
    //#[serde(rename = "CORRELATION")]
    //pub correlation: Option<Correlation>,
    #[serde(rename = "RESULT")]
    pub result: Option<String>,
    #[serde(rename = "RESULT_ERRORS")]
    pub result_errors: Option<String>,
    #[serde(rename = "RESULT_DEBUG")]
    pub result_debug: Option<String>
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)] 
pub struct Service {
    pub number: Option<String>,
    pub severity: Option<String>,
    pub standard_severity: Option<String>,

    #[serde(rename = "TITLE")]
    pub title: Option<String>,
    #[serde(rename = "LAST_UPDATE")]
    pub last_update:Option<String>,
    #[serde(rename  = "PCI_FLAG")]
    pub pci_flag: Option<String>,
    #[serde(rename = "INSTANCE")]
    pub instance: Option<String>,
    #[serde(rename = "VENDOR_REFERENCE_LIST")]
    pub vendor_ref_list:Option<VendorReferenceList>,
    #[serde(rename = "CVE_ID_LIST")]
    pub cve_id_list: Option<CveIdList>,
    #[serde(rename = "BUGTRAQ_ID_LIST")]
    pub bugtraq_id_list: Option<BugTraqIdList>,
    #[serde(rename = "DIAGNOSIS")]
    pub diagnosis: Option<String>,
    #[serde(rename = "DIAGNOSIS_COMMENT")]
    pub diagnosis_comment: Option<String>,
    #[serde(rename = "CONSEQUENCE")]
    pub consequence: Option<String>,
    #[serde(rename = "CONSEQUENCE_COMMENT")]
    pub consequence_comment: Option<String>,
    #[serde(rename = "SOLUTION")]
    pub solution: Option<String>,
    #[serde(rename = "SOLUTION_COMMENT")]
    pub solution_comment: Option<String>,
    #[serde(rename = "COMPLIANCE")]
    pub compliance: Option<Compliance>,
    //#[serde(rename = "CORRELATION")]
    //pub correlation: Option<Correlation>,
    #[serde(rename = "RESULT")]
    pub result: Option<String>

}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)] 
pub struct Practice {
    pub number: String,
    pub severity: Option<String>,
    pub cveid: Option<String>,
    pub standard_severity: Option<String>,

    #[serde(rename = "TITLE")]
    pub title: Option<String>,
    #[serde(rename = "LAST_UPDATE")]
    pub last_update: Option<String>,
    #[serde(rename = "CVSS_BASE")]
    pub cvss_base: Option<String>,
    #[serde(rename = "CVSS_TEMPORAL")]
    pub cvss_temporal: Option<String>,
    #[serde(rename = "CVSS3_BASE")]
    pub cvss3_base: Option<String>,
    #[serde(rename = "CVSS3_TEMPORAL")]
    pub cvss3_temporal: Option<String>,
    #[serde(rename = "CVSS3_VERSION")]
    pub cvss3_version: Option<String>,
    #[serde(rename = "PCI_FLAG")]
    pub pci_flag: Option<String>,
    #[serde(rename = "INSTANCE")]
    pub instance: Option<String>,
    #[serde(rename = "VENDOR_REFERENCE_LIST")]
    pub vendor_reference_list: Option<VendorReferenceList>,
    #[serde(rename = "CVE_ID_LIST")]
    pub cve_id_list: Option<CveIdList>,
    #[serde(rename = "BUGTRAQ_ID_LIST")]
    pub bugtraq_id_list: Option<BugTraqIdList>,
    #[serde(rename = "DIAGNOSIS")]
    pub diagnosis: Option<String>,
    #[serde(rename = "DIAGNOSIS_COMMENT")]
    pub diagnosis_comment: Option<String>,
    #[serde(rename = "CONSEQUENCE")]
    pub consequence: Option<String>,
    #[serde(rename = "CONSEQUENCE_COMMENT")]
    pub consequence_comment: Option<String>,
    #[serde(rename = "SOLUTION")]
    pub solution: Option<String>,
    #[serde(rename = "SOLUTION_COMMENT")]
    pub solution_comment: Option<String>,
    #[serde(rename = "COMPLIANCE")]
    pub compliance: Option<Compliance>,
    //#[serde(rename = "CORRELATION")]
    //pub correlation: Option<Correlation>,
    #[serde(rename = "RESULT")]
    pub result: Option<String>,
    #[serde(rename = "RESULT_ERRORS")]
    pub result_errors: Option<String>,
    #[serde(rename = "RESULT_DEBUG")]
    pub result_debug: Option<String>
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Info {
    pub number: Option<String>,
    pub severity: Option<String>,
    pub standard_severity: Option<String>,

    #[serde(rename = "TITLE")]
    pub title: Option<String>,
    #[serde(rename = "LAST_UPDATE")]
    pub last_update:Option<String>,
    #[serde(rename  = "PCI_FLAG")]
    pub pci_flag: Option<String>,
    #[serde(rename = "INSTANCE")]
    pub instance: Option<String>,
    #[serde(rename = "VENDOR_REFERENCE_LIST")]
    pub vendor_ref_list:Option<VendorReferenceList>,
    #[serde(rename = "CVE_ID_LIST")]
    pub cve_id_list: Option<CveIdList>,
    #[serde(rename = "BUGTRAQ_ID_LIST")]
    pub bugtraq_id_list: Option<BugTraqIdList>,
    #[serde(rename = "DIAGNOSIS")]
    pub diagnosis: Option<String>,
    #[serde(rename = "DIAGNOSIS_COMMENT")]
    pub diagnosis_comment: Option<String>,
    #[serde(rename = "CONSEQUENCE")]
    pub consequence: Option<String>,
    #[serde(rename = "CONSEQUENCE_COMMENT")]
    pub consequence_comment: Option<String>,
    #[serde(rename = "SOLUTION")]
    pub solution: Option<String>,
    #[serde(rename = "SOLUTION_COMMENT")]
    pub solution_comment: Option<String>,
    #[serde(rename = "COMPLIANCE")]
    pub compliance: Option<Compliance>,
    //#[serde(rename = "CORRELATION")]
    //pub : Option<Correlation>,
    #[serde(rename = "RESULT")]
    pub result: Option<String>,
    #[serde(rename = "RESULT_ERRORS")]
    pub result_errors: Option<String>,
    #[serde(rename = "RESULT_DEBUG")]
    pub result_debug: Option<String>
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Compliance {
    #[serde(rename = "COMPLIANCE_INFO")]
    pub compliance_info: Vec<ComplianceInfo>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ComplianceInfo {
    #[serde(rename = "COMPLIANCE_TYPE")]
    pub compliance_type: Option<String>,
    #[serde(rename = "COMPLIANCE_SECTION")]
    pub compliance_section: Option<String>,
    #[serde(rename = "COMPLIANCE_DESCRIPTION")]
    pub compliance_description: Option<String>
}


#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct CveIdList {
    #[serde(rename = "CVE_ID")]
    pub cve_id: Vec<CveId>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct CveId {
    #[serde(rename = "ID")]
    pub id: Option<String>,
    #[serde(rename = "URL")]
    pub url: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct VendorReferenceList {
    #[serde(rename = "VENDOR_REFERENCE")]
    pub vendor_ref: Vec<VendorReference>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct VendorReference {
    #[serde(rename = "ID")]
    pub id: Option<String>,
    #[serde(rename = "URL")]
    pub url: Option<String>,
}


#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct BugTraqIdList {
    #[serde(rename = "BUGTRAQ_ID")]
    pub bug_traq_id: Vec<BugTraqId>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct BugTraqId {
    #[serde(rename = "ID")]
    pub id: Option<String>,
    #[serde(rename = "URL")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Correlation {
    #[serde(rename = "EXPLOITABILITY")]
    pub exploitability: Option<Exploitability>,
    #[serde(rename = "MALWARE")]
    pub malware: Option<Malware>,

}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Exploitability {
    #[serde(rename = "EXPLT_SRC")]
    pub exploit_src: Vec<ExploitSrc>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ExploitSrc {
    #[serde(rename = "SRC_NAME")]
    pub src_name: String,
    #[serde(rename = "EXPLT_LIST")]
    pub explt_list: ExpltList
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ExpltList {
    #[serde(rename = "EXPLT")]
    pub explt_list: Vec<Explt>
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Explt {
    #[serde(rename = "REF")]
    pub refe: String,
    #[serde(rename = "DESC")]
    pub desc: String,
    #[serde(rename = "LINK")]
    pub link: Option<String>
}



#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Malware {
    #[serde(rename = "MW_SRC")]
    pub mw_src: Vec<MWSrc>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct MWSrc {
    #[serde(rename = "SRC_NAME")]
    pub id: Option<String>,
    #[serde(rename = "MW_LIST")]
    pub mw_list: Option<MWList>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct MWList {
    #[serde(rename = "MW_INFO")]
    pub mw_info: Vec<MWInfo>
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct MWInfo {
    #[serde(rename = "MW_ID")]
    pub mw_id: String,
    #[serde(rename = "MW_TYPE")]
    pub mw_type: Option<String>,
    #[serde(rename = "MW_PLATFORM")]
    pub mw_plat: Option<String>,
    #[serde(rename = "MW_ALIAS")]
    pub mw_alias: Option<String>,
    #[serde(rename = "MW_RATING")]
    pub mw_rating: Option<String>,
    #[serde(rename = "UMW_LINK")]
    pub mw_link: Option<String>,
}




#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_header() {

        let header: Header = Header {
            keys: vec![
                Key {
                    value: "USERNAME".to_string(),
                    key: "qualysrs".to_string()
                },
                Key {
                    value: "TITLE".to_string(),
                    key: "VA - CAF".to_string()
                }
            ]
        };

        assert_eq!(
            Scan { ips: vec![], headers: vec![header], value: "scan/1670238615.73708".to_string() },
            from_str("
                <SCAN value=\"scan/1670238615.73708\">
                    <HEADER>
                        <KEY value=\"USERNAME\">qualysrs</KEY>
                        <KEY value=\"TITLE\"><![CDATA[VA - CAF]]></KEY>
                    </HEADER>
                </SCAN>
            ").unwrap()
        );
    
    }


    #[test]
    fn test_ip() {

        let xml = from_str(include_str!("..//files/ip_vuln.xml")).unwrap();

        let vuln: Vuln = Vuln {
            number: "38739".to_string(),
            severity: Some("3".to_string()),
            cveid: None,
            standard_severity: None,

            title: "Deprecated SSH Cryptographic Settings".to_string(),
            last_update: Some("2021-05-26T11:40:40Z".to_string()),
            cvss_base: Some("6.4".to_string()),
            cvss_temporal: Some("4.7".to_string()),
            cvss3_base: Some("6.5".to_string()),
            cvss3_temporal: Some("5.3".to_string()),
            cvss3_version: Some("3.1".to_string()),
            pci_flag: Some("1".to_string()),
            diagnosis: Some("The SSH [...] communicate.".to_string()),
            consequence: Some("A man-in-the-middle [...].<P>".to_string()),
            instance: None,
            vendor_reference_list: None,
            cve_id_list: None,
            bugtraq_id_list: None,
            diagnosis_comment: None,
            consequence_comment: None,
            solution: Some("Avoid using [...] </DL>".to_string()),
            solution_comment: None,
            compliance: None,
            correlation: None,
            result: Some("Type  Namekey exchange  diffie-hellman-group1-sha1".to_string()),
            result_errors: None,
            result_debug: None
        };


        let cat = Cat {
            value: "General remote services".to_string(),
            port: Some("22".to_string()),
            protocol: Some("tcp".to_string()),
            fqdn: None,
            misc: None,
            infos: vec![],
            services: vec![],
            practices: vec![],
            vulns: vec![vuln],
        };

        let vulns = Vulns {
            cats: vec![cat]
        };

        let ip: IP = IP {
            value: "10.168.0.100".to_string(),
            name: "No registered hostname".to_string(),

            os: None,
            os_cpe: None,
            netbios_hostname: None,
            infos: None,
            services: None,
            practices: None,
            network: None,
            vulns: Some(vulns)
        };

        let expected = Scan {
            value: "scan/1670238615.73708".to_string(),
            headers: vec![],
            ips: vec![ip]
        };
        
        assert_eq!(expected, xml);
    }

    #[test]
    fn test_parse() {
        let reports = vec![
            ("base", include_str!("../files/base.xml")),
        ];

        for (_name, report) in reports {
            let _report = from_str(report);
            // println!("report {:?}: {:?}", name, report);
            assert!(true);
        }
    }

}
