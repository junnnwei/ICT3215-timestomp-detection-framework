# ICT3215-Timestomp-Detection-Framework
This project introduces a novel causality-aware timestomping detection framework that bridges this gap. Building upon Plaso’s timeline aggregation capabilities, the proposed system integrates a rule-based anomaly detection engine to evaluate event consistency across diverse artifact sources. For instance, it can flag anomalies such as execution logs that precede file creation timestamps or system events occurring outside expected temporal boundaries. By correlating evidence through causal validation, the tool enhances investigators’ ability to detect timestomping efficiently and reliably. Ultimately, this research aims to contribute a scalable and extensible approach to automated forensic reasoning, improving both accuracy and analyst productivity in digital investigations.

## Usage Notes
Kindly refer to <a href="/ICT3215-PA_G21-UserManual.pdf">ICT3215-PA_G21-UserManual</a> for the user guide detailing the necessary files and workings of our proposed framework.

## Additional Acknowledgements
Credits to Mark Zimmerman and Nirsoft for the provision of supporting tools used within the project such as AmcacheParser.exe and WinPrefetchView respectively.