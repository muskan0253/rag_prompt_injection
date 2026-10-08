# RAG Prompt Injection Laboratory

## 1. Project Description

This project implements a controlled laboratory for studying **Indirect Prompt Injection attacks in Retrieval-Augmented Generation (RAG) systems** and evaluating different defense mechanisms.

The project contains:

- A simulated RAG environment
- A knowledge base containing normal and malicious documents
- Multiple indirect prompt-injection attack scenarios
- Four defense mechanisms
- Multiple experimental configurations
- Automated evaluation
- Sensitivity analysis
- CSV/JSON result generation
- Result visualizations
- A system architecture diagram

The implementation is designed as a controlled cybersecurity research experiment. The language model behavior is simulated using predefined probabilities rather than a real external LLM.

---

# 2. Requirements

Before running the project, install:

- Python 3.8 or higher
- Git
- Matplotlib

Check Python:

```bash
python --version
```

Check Git:

```bash
git --version
```

---

# 3. Download the Project from GitHub

## Step 1: Open a Terminal

Open Command Prompt, PowerShell, Git Bash, or a Linux terminal.

## Step 2: Clone the Repository

Replace `<GITHUB_REPOSITORY_URL>` with the GitHub repository URL.

```bash
git clone <GITHUB_REPOSITORY_URL>
```

Example:

```bash
git clone https://github.com/USERNAME/rag_injection_lab.git
```

## Step 3: Enter the Project Directory

```bash
cd rag_injection_lab
```

The project directory should contain:

```text
rag_injection_lab/
├── README.md
├── rag_lab.py
├── make_architecture_figure.py
└── results/
```

---

# 4. Create a Python Virtual Environment

Creating a virtual environment keeps the project's Python packages separate from the rest of the system.

## Windows

```bash
python -m venv venv
```

Activate it:

### Command Prompt

```bash
venv\Scripts\activate
```

### PowerShell

```powershell
venv\Scripts\Activate.ps1
```

## Linux / macOS / WSL

```bash
python3 -m venv venv
source venv/bin/activate
```

After activation, the terminal normally shows `(venv)` before the current directory.

---

# 5. Install the Required Dependency

Install Matplotlib:

```bash
pip install matplotlib
```

You can verify the installation with:

```bash
pip show matplotlib
```

No external API key or cloud LLM account is required for this implementation.

---

# 6. Project Structure

The complete project is organized as follows:

```text
rag_injection_lab/
│
├── README.md
│
├── rag_lab.py
│
├── make_architecture_figure.py
│
└── results/
    │
    ├── results.json
    ├── summary_by_config.csv
    ├── asr_by_attack.csv
    ├── sweep_spotlight.csv
    ├── chart_asr_utility.png
    ├── chart_heatmap.png
    └── fig_architecture.png
```

---

# 7. Source Files

## 7.1 `rag_lab.py`

`rag_lab.py` is the **main source file** of the project.

It contains the complete controlled RAG prompt-injection laboratory and performs the following tasks:

### Knowledge Base

The file defines the documents used by the simulated RAG system.

The knowledge base contains normal documents as well as documents containing malicious instructions.

The malicious documents represent the indirect prompt-injection condition where an attacker places instructions inside information that may later be retrieved by the RAG system.

### Retrieval

The project uses a TF-IDF-based retrieval mechanism with cosine similarity.

The user asks a question, and the retrieval component selects the most relevant document/chunk from the knowledge base.

The retrieved content is then passed into the simulated RAG prompt.

### Attack Scenarios

`rag_lab.py` contains the attack scenarios used in the experiment.

The laboratory evaluates different forms of indirect prompt injection, including:

1. Direct Override
2. Paraphrased Injection
3. Delimiter Escape
4. Hidden HTML Comment
5. Zero-Width Character Injection
6. Base64 Injection
7. Multilingual / Hindi Injection
8. Secret Leakage
9. Image Exfiltration
10. Misinformation / Phishing
11. Denial of Service
12. Authority Spoofing
13. Adaptive Soft Instruction

These attacks are placed inside retrieved content rather than being supplied directly by the user, which models the indirect prompt-injection threat.

### Defense Mechanisms

The main file implements four defense layers.

#### D1: Injection Detector

The detector searches retrieved content for suspicious signals such as:

- Instruction override phrases
- Directive wording
- Requests for secrets
- Role or authority spoofing
- Fake context delimiters
- External links
- Images
- Hidden HTML comments
- Encoded instructions
- Multilingual override instructions

A suspicious chunk can be rejected before it reaches the model.

#### D2: Input Sanitizer

The sanitizer cleans retrieved content before it is inserted into the model context.

It handles techniques such as:

- Unicode normalization
- Removal of zero-width characters
- Removal of HTML comments
- Removal of fake delimiter tags
- Removal of suspicious instruction sentences
- Replacement of Markdown images
- Replacement of non-allowed external links

#### D3: Context Isolation / Spotlighting

The spotlighting mechanism marks retrieved content using a fresh random delimiter/tag for each query.

The purpose is to make it harder for malicious retrieved content to escape its intended data context by pretending to be system-level instructions.

#### D4: Output Guard

The output guard checks the final generated response.

It looks for dangerous output such as:

- Secret values
- Canary tokens
- Internal policy text
- Markdown images
- Non-allowed external links

If harmful content is detected, the response is replaced with a safe refusal message.

### Simulated Model

The project does not call a real external LLM.

Instead, `rag_lab.py` contains a simulated model that approximates model behavior using predefined probabilities.

The simulation models behaviors such as:

- Following malicious instructions
- Interpreting fake delimiters
- Processing encoded instructions
- Following instructions after spotlighting
- Producing simulated sensitive output
- Producing simulated image/link output

This allows the experiment to be repeated with controlled and reproducible behavior.

### Experimental Configurations

The experiment compares different defense configurations.

The configurations include:

```text
C0 - No Defense
C1 - Injection Detector
C2 - Input Sanitizer
C3 - Spotlighting
C4 - Output Guard
C5 - Detector + Sanitizer
C6 - All Defense Layers
```

### Evaluation

The `eval` command executes the experiment across the defined attacks, questions, configurations, and random seeds.

It generates the experimental result files in the `results/` directory.

---

# 8. `make_architecture_figure.py`

`make_architecture_figure.py` is used to generate the project's system architecture figure.

It creates the visual representation of the RAG security architecture, including:

```text
Attacker
   |
   v
Knowledge Base
   |
   v
Retriever
   |
   v
D1 Injection Detector
   |
   v
D2 Input Sanitizer
   |
   v
D3 Context Isolation / Spotlighting
   |
   v
LLM / Simulated Model
   |
   v
D4 Output Guard
   |
   v
Final Answer
```

The generated architecture image is stored in:

```text
results/fig_architecture.png
```

This script is separate from `rag_lab.py` so that the architecture figure can be regenerated without running the complete experiment.

---

# 9. Result Files

The `results/` directory contains the outputs produced by the experiment.

## `results.json`

This file stores the complete experiment results in JSON format.

It contains the detailed results generated during evaluation, including the tested configurations and measured outcomes.

JSON is used so that the experiment results can be loaded and processed programmatically.

---

## `summary_by_config.csv`

This CSV file contains the aggregated results for each defense configuration.

It is used to compare configurations such as:

```text
C0
C1
C2
C3
C4
C5
C6
```

The file contains the main evaluation metrics for comparing the effectiveness of the defenses.

---

## `asr_by_attack.csv`

This file contains Attack Success Rate (ASR) results broken down by attack type.

It allows the researcher to determine which attacks are more difficult for each defense configuration to stop.

---

## `sweep_spotlight.csv`

This file contains the results of the spotlighting sensitivity analysis.

It is generated by the `sweep` command and is used to study how changes in the spotlighting-related parameters affect attack success.

---

## `chart_asr_utility.png`

This visualization compares:

- Attack Success Rate
- Benign utility

across the different defense configurations.

It provides a visual comparison between security effectiveness and preservation of normal system behavior.

---

## `chart_heatmap.png`

This visualization presents attack results as a heatmap.

It makes it easier to identify which combinations of:

- Attack types
- Defense configurations

produce higher or lower attack success.

---

## `fig_architecture.png`

This is the system architecture diagram generated by:

```bash
python make_architecture_figure.py
```

---

# 10. Running the Project

## 10.1 Run a Single Attack Demonstration

The `demo` command runs one selected attack and displays its behavior across the defense configurations.

Run:

```bash
python rag_lab.py demo --attack 6 --q 0
```

Here:

```text
--attack 6
```

selects attack number 6.

```text
--q 0
```

selects question/query number 0.

The demonstration is useful for checking the behavior of an individual attack before running the complete experiment.

---

# 11. Run the Complete Experiment

Run:

```bash
python rag_lab.py eval
```

This executes the complete evaluation.

The experiment tests the attack scenarios against the different defense configurations and generates the result files.

The generated files are placed inside:

```text
results/
```

After execution, check:

```text
results/results.json
results/summary_by_config.csv
results/asr_by_attack.csv
results/chart_asr_utility.png
results/chart_heatmap.png
```

---

# 12. Run Sensitivity Analysis

To evaluate the spotlighting configuration under different parameter conditions, run:

```bash
python rag_lab.py sweep
```

The generated sensitivity-analysis data is saved as:

```text
results/sweep_spotlight.csv
```

---

# 13. Generate the Architecture Diagram

Run:

```bash
python make_architecture_figure.py
```

The generated diagram will be saved as:

```text
results/fig_architecture.png
```

---

# 14. Recommended Execution Order

For a complete execution from a fresh clone, use the following order:

```bash
git clone <GITHUB_REPOSITORY_URL>
cd rag_injection_lab
```

Create the virtual environment:

```bash
python -m venv venv
```

Activate it.

Windows PowerShell:

```powershell
venv\Scripts\Activate.ps1
```

Linux / macOS / WSL:

```bash
source venv/bin/activate
```

Install the dependency:

```bash
pip install matplotlib
```

Run a demonstration:

```bash
python rag_lab.py demo --attack 6 --q 0
```

Run the complete experiment:

```bash
python rag_lab.py eval
```

Run the sensitivity analysis:

```bash
python rag_lab.py sweep
```

Generate the architecture figure:

```bash
python make_architecture_figure.py
```

---

# 15. GitHub Usage

After cloning the repository, all source code and existing result files are available locally.

To check the project files:

```bash
dir
```

on Windows, or:

```bash
ls
```

on Linux/macOS/WSL.

To check the results:

```bash
dir results
```

or:

```bash
ls results
```

---

# 16. Important Note About the Implementation

This implementation is a **controlled simulation** of a RAG prompt-injection environment.

It does not require:

- An OpenAI API key
- An Anthropic API key
- A Gemini API key
- A cloud vector database
- An external LLM service

The simulated model is intentionally used to make the security experiment repeatable and controlled.

The results produced by the program therefore represent the behavior of the experimental simulation and should not be interpreted as measurements from a specific commercial LLM.

---

# 17. GitHub Repository

**GitHub Repository: **

`https://github.com/muskan0253/rag_prompt_injection.git`

