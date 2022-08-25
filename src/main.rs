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
        .version("0.4.6")
        .author("Anton Gura <satandyh@yandex.ru>")
        .about("A Trivy plugin that scans the filesystem and skips all packages except for explicitly specified dependencies.\nImportant! You have to use '--' to pass flags to plugin. Without it all flags will be passed as global.")
        .override_usage("trivy exp-dep -- [OPTIONS]\n    # Scan fs\n      trivy exp-dep -- -p /path/to/project\n    # Scan fs and filter by severity\n      trivy exp-dep -- --path /path/to/project --global --severity CRITICAL")
        .arg(Arg::with_name("path")
            .short('p')
            .long("path")
            //.required(true)
            .takes_value(true)
            .default_value_os(env::current_dir()?.as_os_str())
            .help("Directory where to scan. Current Working dir is default."))
        .arg(Arg::with_name("global")
            .long("global")
            .global(true)
            .takes_value(true)
            .multiple(true)
            .allow_hyphen_values(true)
            .required(false)
            .help("Indicate that all flags after will be passed as trivy global/fs options.\nPositional, should be after \"-p/-h/--\" options."))
        .get_matches();

    _project_path = exp_dep.value_of("path").unwrap();
    //    _project_path = exp_dep.get_one::<&str>("path").unwrap();
    //let mut global: Vec<&str>;

    let mut global: Vec<&str> = vec![""];
    let gl: i8; // supprot var for global values - show does it present or not
    if !exp_dep.value_of("global").is_none() {
        global = exp_dep.values_of("global").unwrap().collect();
        gl = 1;
    } else {
        gl = 2;
    }
    if !path::Path::new(_project_path).is_dir() {
        eprintln!("No such directory to scan {}", _project_path);
        std::process::exit(1)
    }

    /* GET RESULTS BEFORE ANALYZE */
    (_prescan_pkg, _) = findpkg(&global, _project_path, gl);

    /* FILTERFIND */
    for entry in WalkDir::new(_project_path)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        /* Pipfile and pyproject.toml */
        //case insensitive by lowercase
        if entry
            .file_name()
            .to_ascii_lowercase()
            .to_string_lossy()
            .ends_with("pipfile")
            || entry
                .file_name()
                .to_ascii_lowercase()
                .to_string_lossy()
                .ends_with("pyproject.toml")
        {
            // read file
            let input = File::open(entry.path())?;
            let buffered = std::io::BufReader::new(input);
            // stored elements for filter
            let mut exp_set: HashMap<String, Regex> = HashMap::new();
            for element in _prescan_pkg.clone() {
                exp_set.insert(
                    element.to_string(),
                    Regex::new(format!(r#"(?i)^\s*({})\s*=\s*"#, element.as_str()).as_str())
                        .unwrap(),
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

        /* requirements.txt */
        //case insensitive by lowercase
        if entry
            .file_name()
            .to_ascii_lowercase()
            .to_string_lossy()
            .ends_with("requirements.txt")
        {
            // read file
            let input = File::open(entry.path())?;
            let buffered = std::io::BufReader::new(input);
            // stored elements for filter
            let mut exp_set: HashMap<String, Regex> = HashMap::new();
            for element in _prescan_pkg.clone() {
                exp_set.insert(
                    element.to_string(),
                    Regex::new(
                        format!(r#"(?i)^\s*[^#]*\s*({})\s*(?:<|>|\^|=)+"#, element.as_str())
                            .as_str(),
                    )
                    .unwrap(),
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

        /* package.json */
        //case insensitive by lowercase
        if entry
            .file_name()
            .to_ascii_lowercase()
            .to_string_lossy()
            .ends_with("package.json")
        {
            // read file
            let input = File::open(entry.path())?;
            let buffered = std::io::BufReader::new(input);
            // stored elements for filter
            let mut exp_set: HashMap<String, Regex> = HashMap::new();
            for element in _prescan_pkg.clone() {
                exp_set.insert(
                    element.to_string(),
                    Regex::new(
                        format!(
                            r#"(?i)^\s*"(?:\W*[^/]*\W*)/?({})"\s*:\s*"\S+""#,
                            element.as_str()
                        )
                        .as_str(),
                    )
                    .unwrap(),
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
        for opt in &global {
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
        std::fs::remove_file(policy_path.to_str().unwrap())?;
        std::process::exit(1);
    } else {
        String::from_utf8(scanres.stdout)
            .into_iter()
            .for_each(|x| print!("{}", x));
    }
    std::fs::remove_file(policy_path.to_str().unwrap())?;

    Ok(())
}

/*
This function start trivy and store results into temp json file.
After it read and analyze this file and gets all vulnerable packages into HashSet<String>.
Temp file removed at end of function.
*/
fn findpkg(
    global: &Vec<&str>,
    project_path: &str,
    gl_stat: i8,
) -> (HashSet<String>, std::io::Result<()>) {
    let mut output: HashSet<String> = HashSet::new();
    let result: std::io::Result<()>;
    // path for temp file
    let temp_file = path::Path::new(env::temp_dir().as_path()).join("prescan.json");

    /* Make first scan and form some results with we will analyze after */
    let mut firstscan = Command::new("trivy");
    if gl_stat == 1 {
        firstscan
            .arg("fs")
            .arg("-q")
            .arg("-f")
            .arg("json")
            .arg("-o")
            .arg(&temp_file.to_str().unwrap());
        for opt in global {
            firstscan.arg(opt);
        }
        firstscan.arg(project_path);
    } else {
        firstscan.args([
            "fs",
            "-q",
            "-f",
            "json",
            "-o",
            &temp_file.to_str().unwrap(),
            project_path,
        ]);
    }
    let stat = firstscan.output();
    let cmd_out = firstscan.output().unwrap();
    if !&stat.unwrap().status.success() {
        String::from_utf8(cmd_out.stderr)
            .into_iter()
            .for_each(|x| eprint!("{}", x));
        std::process::exit(1);
    }

    /* Analyze results and get only packet names */
    if !path::Path::new(&temp_file.to_str().unwrap()).exists() {
        eprintln!(
            "No such file or it's can't be read {}",
            &temp_file.to_str().unwrap()
        );
        std::process::exit(1)
    }
    let json_str = {
        let jsondata = std::fs::read_to_string(&temp_file.to_str().unwrap()).unwrap();
        serde_json::from_str::<Value>(&jsondata).unwrap()
    };

    result = std::fs::remove_file(&temp_file.to_str().unwrap());

    if json_str.get("Results") != None {
        for index1 in json_str["Results"].as_array().unwrap() {
            if index1.get("Vulnerabilities") != None {
                for index2 in index1["Vulnerabilities"].as_array().unwrap() {
                    if index2.get("PkgName") != None {
                        output.insert(
                            index2["PkgName"].to_string().replace('"', ""), // damn quotes
                        );
                    }
                }
            }
        }
    } else {
        String::from_utf8(cmd_out.stdout)
            .into_iter()
            .for_each(|x| print!("{}", x));
        std::process::exit(0);
    };

    (output, result)
}
