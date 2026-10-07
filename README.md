# RAG Prompt-Injection Lab (CA-2 Cyber Security)

Shows how a poisoned document can hijack a RAG chatbot, and how 4 defenses reduce the damage.
Pure Python 3 (standard library). Only the charts need: `pip install matplotlib`.

## Commands
python rag_lab.py demo --attack 6 --q 0   # step-by-step demo of ONE attack (use this in your video)
python rag_lab.py eval                    # full experiment -> results/*.csv and charts
python rag_lab.py sweep                   # sensitivity test
python make_architecture_figure.py        # redraws the architecture figure

Attack numbers for --attack: 1 Direct override, 2 Paraphrased, 3 Delimiter escape, 4 Hidden HTML comment,
5 Zero-width, 6 Base64, 7 Hindi, 8 Secret leak, 9 Image exfiltration, 10 Misinformation/phishing,
11 Denial of service, 12 Authority spoof, 13 Adaptive soft instruction.  --q = question number 0 to 7.

## Files
rag_lab.py  - whole implementation (retriever, attacks, 4 defenses, simulated LLM, experiments)
results/    - CSV tables and PNG charts used in the report

## Note
The LLM is a SIMULATION (deterministic, no API key). It tests the pipeline defenses, not a specific
commercial model. Say this clearly in your viva/video.
