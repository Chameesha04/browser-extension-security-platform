⚙️ Setup Guide

This guide explains how to install, configure, and run the Chrome Extension Security AI Agent.

📋 Prerequisites

Before setting up the agent, make sure you have:

Python 3.11 or newer
A Google Gemini API key
Access to the custom endpoint scanner
Git
PowerShell on Windows, or a Bash-compatible terminal on macOS/Linux
1. Clone the Repository
git clone <repository-url>
cd <project-directory>

2. Create a Python Virtual Environment
Windows PowerShell
python -m venv venv


Activate the environment:

.\venv\Scripts\Activate.ps1


You should see:

(venv) PS C:\...\project>

macOS / Linux
python3 -m venv venv
source venv/bin/activate

3. Install Dependencies

Install the project dependencies:

pip install -r requirements.txt


If Google ADK is not already included in requirements.txt, install it separately:

pip install google-adk


For environment variable management:

pip install python-dotenv

Important

The correct package for Google's Agent Development Kit is:

google-adk


Do not install:

pip install google adk


That installs unrelated packages named google and adk.

4. Verify Google ADK

Verify that ADK is installed:

adk --help


You can also check the installed package:

pip show google-adk


Check which executable is being used on Windows:

where.exe adk


The executable should point to your virtual environment, for example:

...\project\venv\Scripts\adk.exe

5. Configure Gemini API

The agent uses the Google Gemini API for AI reasoning.

Create a .env file in the project root:

.env


Add:

GEMINI_API_KEY=your_gemini_api_key


Replace:

your_gemini_api_key


with your actual API key.

Example
GEMINI_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxx


Do not share your API key or commit it to Git.

6. Configure the Scanner Endpoint

The agent communicates with the custom Chrome extension security scanner through an endpoint.

Add the scanner endpoint to .env.

For example:

GEMINI_API_KEY=your_gemini_api_key
SCANNER_ENDPOINT=http://localhost:5000


If your scanner uses a different endpoint:

SCANNER_ENDPOINT=https://your-scanner.example.com/api


Use the endpoint expected by your agent's scanner tools.

7. Environment File

A typical .env file may look like:

GEMINI_API_KEY=your_gemini_api_key
SCANNER_ENDPOINT=http://localhost:5000


Additional environment variables can be added depending on the scanner implementation.

For example:

GEMINI_API_KEY=your_gemini_api_key
SCANNER_ENDPOINT=http://localhost:5000
SCANNER_API_KEY=your_scanner_api_key


Only include variables actually required by your implementation.

8. Protect Environment Variables

Add .env and your virtual environment to .gitignore.

Example:

venv/
.env
__pycache__/
*.pyc


Never commit API keys, scanner credentials, tokens, or other secrets.

9. Project Structure

A recommended structure is:

project/
│
├── agent/
│   ├── __init__.py
│   ├── agent.py
│   │
│   └── tools/
│       ├── scanner.py
│       ├── analysis.py
│       └── history.py
│
├── .env
├── .gitignore
├── requirements.txt
├── README.md
└── SETUP.md


The exact structure depends on your implementation.

10. Configure the ADK Agent

Your ADK agent should expose a root agent.

A simplified example:

from google.adk.agents import Agent

root_agent = Agent(
    name="chrome_extension_security_agent",
    model="gemini-2.5-flash",
    instruction="""
    You are a cybersecurity assistant specializing in
    Chrome extension security analysis.

    Use the available scanner tools to retrieve security
    information and explain the results clearly.
    """
)


Your actual agent will also include the tools used to communicate with the custom scanner.

11. Start the Custom Scanner

The AI agent requires the custom scanner endpoint to be available when performing real-time scans.

For example, if your scanner runs locally:

http://localhost:5000


Start the scanner using its own startup instructions.

Then verify that the endpoint is reachable before starting the ADK agent.

For example:

Invoke-WebRequest http://localhost:5000


The exact URL depends on your scanner.

12. Start the ADK Agent

Make sure the virtual environment is activated:

.\venv\Scripts\Activate.ps1


Then run:

adk web


The ADK development interface should start locally.

Follow the URL displayed in the terminal to open the agent interface.

13. Test the Agent

Once the agent is running, try:

Run a security scan of my Chrome extensions.


Then:

Show me the high-risk extensions.


Try analyzing a specific extension:

Why is this extension considered high risk?


Permission analysis:

What permissions does this extension have?


Historical analysis:

Has this extension's risk changed over time?


Report generation:

Generate a security report for my browser extensions.

14. Troubleshooting
adk command is not recognized

Check:

where.exe adk


Then verify:

pip show google-adk


If it is missing:

pip install google-adk


Make sure your virtual environment is activated.

adk web exits immediately

First check the installation:

adk --help
pip show google-adk
where.exe adk


Make sure you installed:

google-adk


and not:

adk


If you previously installed the unrelated adk package, remove it:

pip uninstall adk google -y
pip install google-adk


Then retry:

adk web

Gemini authentication error

Check your .env file:

GEMINI_API_KEY=your_gemini_api_key


Make sure:

The API key is valid.
The environment variable name matches your implementation.
The .env file is in the expected location.
Your application actually loads the environment variables.
Scanner connection error

Check:

SCANNER_ENDPOINT=http://localhost:5000


Then make sure the scanner is running.

Also verify that the endpoint configured in the agent matches the endpoint exposed by your scanner.

ModuleNotFoundError

Activate the virtual environment:

.\venv\Scripts\Activate.ps1


Then reinstall dependencies:

pip install -r requirements.txt


Check the installed packages:

pip list

15. Updating Dependencies

To update pip:

python -m pip install --upgrade pip


To update project dependencies, modify requirements.txt and reinstall:

pip install -r requirements.txt


For reproducible environments, keep important dependency versions pinned in requirements.txt.

🔐 Security Checklist

Before running the project:

 Python virtual environment created
 Dependencies installed
 google-adk installed
 Gemini API key configured
 Scanner endpoint configured
 Custom scanner running
 .env excluded from Git
 API keys not committed
 Scanner access restricted to authorized systems
 ADK agent starts successfully
🚀 Quick Start

For an existing checkout, the shortest setup is:

python -m venv venv
.\venv\Scripts\Activate.ps1

pip install -r requirements.txt
pip install google-adk python-dotenv


Create .env:

GEMINI_API_KEY=your_gemini_api_key
SCANNER_ENDPOINT=http://localhost:5000


Then start the agent:

adk web


Make sure the custom scanner is running before requesting a new scan.

🧹 Deactivating the Environment

When finished:

deactivate


To reactivate it later:

.\venv\Scripts\Activate.ps1