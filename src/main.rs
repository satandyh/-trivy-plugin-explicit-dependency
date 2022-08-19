use clap::{App, Arg};
use regex::{self, Regex};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::env;
use std::io::BufRead;
use std::path;
use std::process::Command;
use walkdir::WalkDir;

fn main() -> std::io::Result<()> {
    // vars
    let mut _PROJECT_PATH: &str; // project path
    let mut _PRESCAN_PKG: HashSet<String> = HashSet::new(); // all founded vulnerable packages from prescan
    let mut _VULN_PKG: HashSet<String> = HashSet::new(); // only vulnerable packages that exist in package.json (explicit dependencies)
    let mut _IGNORE_PKG: HashSet<String> = HashSet::new(); // all vulnerable packages that not exist in package.json - they should be ignored

    let exp_dep = App::new("trivy-exp-dep")
        .version("0.1.2")
        .author("Anton Gura <satandyh@yandex.ru>")
        .about("A Trivy plugin that scans the filesystem and skips all packages except for explicitly specified dependencies.")
        .arg(Arg::with_name("path")
            .short('p')
            .long("path")
            //.required(true)
            .takes_value(true)
            .default_value_os(env::current_dir()?.as_os_str())
            .help("Directory where to scan. Current Working dir is default."))
        .arg(Arg::with_name("global")
            .long("global")
            //.last(true)
            .global(true)
            .takes_value(true)
            .multiple(true)
            .allow_hyphen_values(true)
            .required(false)
            .help("Indicate that all flags after will be passed as trivy global/fs options.\nPositional, should be after \"-p/-h/--\" options."))
        .get_matches();

    _PROJECT_PATH = exp_dep.value_of("path").unwrap();
    if !path::Path::new(_PROJECT_PATH).is_dir() {
        eprintln!("No such directory to scan {}", _PROJECT_PATH);
        std::process::exit(1)
    }
    let global: Vec<&str>;

    /* FIRSTSCAN */
    let prescan = path::Path::new(env::temp_dir().as_path()).join("prescan.json");
    let mut firstscan = Command::new("trivy");
    if !exp_dep.value_of("global").is_none() {
        global = exp_dep.values_of("global").unwrap().collect();
        firstscan
            .arg("fs")
            .arg("-q")
            .arg("-f")
            .arg("json")
            .arg("-o")
            .arg(prescan.to_str().unwrap());
        for opt in global {
            firstscan.arg(opt);
        }
        firstscan.arg(_PROJECT_PATH);
    } else {
        firstscan.args([
            "fs",
            "-q",
            "-f",
            "json",
            "-o",
            prescan.to_str().unwrap(),
            _PROJECT_PATH,
        ]);
    }
    let firstscanres = firstscan.output()?;
    if !firstscanres.status.success() {
        String::from_utf8(firstscanres.stderr)
            .into_iter()
            .for_each(|x| eprintln!("{:#?}", x));
        std::process::exit(1);
    }

    /* FINDFILES */
    if !path::Path::new(prescan.to_str().unwrap()).exists() {
        eprintln!(
            "No such file or it's can't be read {}",
            prescan.to_str().unwrap()
        );
        std::process::exit(1)
    }
    let prescan_json = {
        let jsondata = std::fs::read_to_string(prescan.to_str().unwrap()).unwrap();
        serde_json::from_str::<Value>(&jsondata).unwrap()
    };

    if prescan_json.get("Results") != None {
        for index1 in 0..prescan_json["Results"].as_array().unwrap().len() {
            for index2 in 0..prescan_json["Results"][index1]["Vulnerabilities"]
                .as_array()
                .unwrap()
                .len()
            {
                _PRESCAN_PKG.insert(
                    prescan_json["Results"][index1]["Vulnerabilities"][index2]["PkgName"]
                        .to_string()
                        .replace('"', ""), // fucking quotes
                );
            }
        }
    } else {
        // the same as if _PRESCAN_PKG.len() == 0
        std::fs::copy(
            prescan.to_str().unwrap(),
            format!("{}{}", _PROJECT_PATH, "/trivy.json".to_string()),
        )?;
        std::fs::remove_file(prescan.to_str().unwrap())?;
        std::process::exit(0);
    }
    // check
    for i in _PRESCAN_PKG.clone() {
        println!("--> {}", i);
    }

    /* FILTERFIND */
    for entry in WalkDir::new(_PROJECT_PATH)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        //case insensitive by lowercase
        if entry
            .file_name()
            .to_ascii_lowercase()
            .to_string_lossy()
            .ends_with("pipfile")
        {
            // read file
            let input = std::fs::File::open(entry.path())?;
            let buffered = std::io::BufReader::new(input);
            // stored elements for filter
            let mut exp_set: HashMap<String, Regex> = HashMap::new();
            for element in _PRESCAN_PKG.clone() {
                exp_set.insert(
                    element.to_string(),
                    regex::Regex::new(format!(r"(?i)(^\s*{}\s*=\s*)", element.as_str()).as_str())
                        .unwrap(),
                );
            }
            // filter thru all regex
            for line in buffered.lines().filter_map(|x| x.ok()) {
                for (key, value) in exp_set.iter() {
                    if value.is_match(line.as_str()) {
                        _VULN_PKG.insert(key.to_string());
                    }
                }
            }
        }
    }
    // check
    for j in _VULN_PKG.clone() {
        println!("==> {}", j);
    }
    //_IGNORE_PKG = _PRESCAN_PKG.clone().difference(&_VULN_PKG.clone()).collect()::<HashSet<String>>();
    //for k in _IGNORE_PKG.clone() {
    //    println!("++> {}", k);
    //}
    Ok(())
}
