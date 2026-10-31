# agurim

agurim: a multi-dimensional flow aggregation tool

This source tree contains the tools to build the agurim web server,
including the source code of the re-aggregation engine and web
user interface.

# Layout

	/usr/local/bin/agurim
		the agurim binary.
	/usr/local/bin/aguri3
		the aguri3 binary for primary aggregation.
	cgi-bin/
		the cgi directory.
	agurim_home/
		the home direcotry for the web content.
	data_dir/
		the top directory for the datasets.
		the agurim data files are stored under this directory.

		dsname/  # dataset name
		  yyyy.agr # yearly data with 24-hour resolution
		  yyyymm/  # month dir
		    yyyymm.agr # monthly data with 2-hour resolution
		    yyyymmdd/  # day dir
		      yyyymmdd.agr # daily data with 5-min resolution
		      yyyymmdd.HHMMSS.agr # high resolution data

# Install

  0. populate data under 'data_dir'.

   Use 'scripts/reaggregate.sh' for reaggregating datasets.
   See 'scripts/README.md' for more detail.

  1. install the aguirm binary to '/usr/local/bin/agurim'.

	`% cd src; make; sudo make install`

  2. copy 'agurim/cgi-bin/*' to 'cgi-bin'.
    - edit 'myagurim.cgi'.
      - 'agurimcmd': absolute path to the agurim binary command.
      - 'data_dir': path to the datasets (relative from the cgi-bin page).
      - 'def_dsname': default dataset name.

    if the python path isn't '/usr/local/bin/python', change
    the path in the cgi scripts.

    make sure that this cgi-bin directroy is configured properly for
    your web server.  you can try `http://your_server/cgi_path/test.cgi`.

  3. copy `index.html detail.html about.html css/ img/ js/ fonts/`
    to 'agurim_home'.
    - edit 'index.html' and customize 'datasets' if you have multiple datasets.
    - edit 'cgi_path' for 'cgi-bin', in 'js/myagurim.js'.
    - edit 'timeoffset', timezone offset, in 'js/myagurim.js'.

# AI Multi-Agent Intelligence (Google ADK)

Agurim includes a built-in multi-agent Network Operations Center (AI NOC Team) powered by [Google ADK (Agent Development Kit)](https://github.com/google/adk-python):

- **AgurimNocCoordinator (`LlmAgent`)**: Lead orchestrator that interfaces with users and dispatches tasks.
- **AgurimDataEngineer (`LlmAgent`)**: Translates queries into Agurim re-aggregation parameters and extracts HHH records.
- **ParallelAnomalyTeam (`ParallelAgent`)**: Parallel triage across:
  - `VolumeAnalyst`: Bandwidth/packet spikes and burst ratios.
  - `ProtoSignatureAnalyst`: Protocol/port amplification (DNS/NTP/SSDP) and sweeps.
  - `ThreatIntelAnalyst`: Prefix WHOIS, ASN attribution, and CDN classification.
- **MitigationSafetyPipeline (`SequentialAgent`)**:
  - `MitigationPlanner`: Synthesizes BGP Flowspec (RFC 8955), Cisco ACL, and Linux nftables rules.
  - `SafetyCritic`: Audits rules to ensure critical infrastructure is not blocked.
- **Autonomous Sentinel (`agurim_agent.sentinel`)**: Continuous watchdog monitoring incoming flows and generating incident alerts.

### Quickstart

1. **Configure API credentials** (optional for local/test mode):
   ```bash
   cp agurim_agent/.env.example agurim_agent/.env
   # Edit agurim_agent/.env with your GEMINI_API_KEY
   ```

2. **Launch Dev Server with AI Copilot**:
   ```bash
   python3 scripts/serve.py 8000
   ```
   Open `http://localhost:8000/index.html` and click **"AI Copilot"** to interact with the multi-agent team.

3. **Run ADK CLI & Developer Web UI**:
   ```bash
   # CLI chat with the NOC Coordinator
   adk run agurim_agent

   # ADK Visual Web UI
   adk web
   ```

4. **Run Autonomous Sentinel Watchdog**:
   ```bash
   # One-shot scan
   python3 -m agurim_agent.sentinel --once

   # Continuous monitoring
   python3 -m agurim_agent.sentinel --interval 60 --threshold 20000000
   ```




