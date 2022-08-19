use clap::{App, Arg};
use regex::Regex;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::File;
use std::io::{BufRead, Write};
use std::path;
use std::process::Command;
use walkdir::WalkDir;

fn main() -> std::io::Result<()> {
    // vars
    let mut _project_path: &str; // project path
    let mut _prescan_pkg: HashSet<String> = HashSet::new(); // all founded vulnerable packages from prescan
    let mut _vuln_pkg: HashSet<String> = HashSet::new(); // only vulnerable packages that exist in package.json (explicit dependencies)
    let mut _ignore_pkg: HashSet<String> = HashSet::new(); // all vulnerable packages that not exist in package.json - they should be ignored

    /* get args */
    let exp_dep = App::new("trivy-exp-dep")
        .version("0.1.3")
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

    _project_path = exp_dep.value_of("path").unwrap();
    if !path::Path::new(_project_path).is_dir() {
        eprintln!("No such directory to scan {}", _project_path);
        std::process::exit(1)
    }
    let mut global: Vec<&str>;

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
        firstscan.arg(_project_path);
    } else {
        firstscan.args([
            "fs",
            "-q",
            "-f",
            "json",
            "-o",
            prescan.to_str().unwrap(),
            _project_path,
        ]);
    }
    let firstscanres = firstscan.output()?;
    if !firstscanres.status.success() {
        String::from_utf8(firstscanres.stderr)
            .into_iter()
            .for_each(|x| eprint!("{}", x));
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
                _prescan_pkg.insert(
                    prescan_json["Results"][index1]["Vulnerabilities"][index2]["PkgName"]
                        .to_string()
                        .replace('"', ""), // fucking quotes
                );
            }
        }
    } else {
        String::from_utf8(firstscanres.stdout)
            .into_iter()
            .for_each(|x| print!("{}", x));
        std::fs::remove_file(prescan.to_str().unwrap())?;
        std::process::exit(0);
    }

    /* FILTERFIND */
    for entry in WalkDir::new(_project_path)
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
            let input = File::open(entry.path())?;
            let buffered = std::io::BufReader::new(input);
            // stored elements for filter
            let mut exp_set: HashMap<String, Regex> = HashMap::new();
            for element in _prescan_pkg.clone() {
                exp_set.insert(
                    element.to_string(),
                    Regex::new(format!(r"(?i)(^\s*{}\s*=\s*)", element.as_str()).as_str()).unwrap(),
                );
            }
            // filter thru all regex
            for line in buffered.lines().filter_map(|x| x.ok()) {
                for (key, value) in exp_set.iter() {
                    if value.is_match(line.as_str()) {
                        _vuln_pkg.insert(key.to_string());
                    }
                }
            }
        }
    }
    _ignore_pkg = _prescan_pkg
        .clone()
        .difference(&_vuln_pkg.clone())
        .cloned()
        .collect();

    /* CREATEPOLICY */
    let policy_path = path::Path::new(env::temp_dir().as_path()).join("ignore_policy.rego");
    let mut output = File::create(policy_path.clone())?;
    let pola = "package trivy\nimport data.lib.trivy\ndefault ignore = false";
    let polb = format!(
        "ignore_pkgs := {}{}{}",
        "{\"",
        _ignore_pkg
            .into_iter()
            .collect::<Vec<String>>()
            .join("\",\""),
        "\"}"
    );
    let polc = "ignore {\ninput.PkgName == ignore_pkgs[_]\n}\n";
    let policy_cotent = [pola, polb.as_str(), polc].join("\n");
    write!(output, "{}", policy_cotent)?;

    /* SCAN */
    let mut scan = Command::new("trivy");
    if !exp_dep.value_of("global").is_none() {
        global = exp_dep.values_of("global").unwrap().collect();
        scan.arg("fs")
            .arg("--ignore-policy")
            .arg(policy_path.clone().as_os_str().to_str().unwrap());
        for opt in global {
            scan.arg(opt);
        }
        scan.arg(_project_path);
    } else {
        scan.args([
            "fs",
            "--ignore-policy",
            policy_path.clone().as_os_str().to_str().unwrap(),
            _project_path,
        ]);
    }
    let scanres = scan.output()?;
    if !scanres.status.success() {
        String::from_utf8(scanres.stderr)
            .into_iter()
            .for_each(|x| eprint!("{}", x));
        std::fs::remove_file(prescan.to_str().unwrap())?;
        std::fs::remove_file(policy_path.to_str().unwrap())?;
        std::process::exit(1);
    } else {
        String::from_utf8(scanres.stdout)
            .into_iter()
            .for_each(|x| print!("{}", x));
    }
    std::fs::remove_file(prescan.to_str().unwrap())?;
    std::fs::remove_file(policy_path.to_str().unwrap())?;

    Ok(())
}
