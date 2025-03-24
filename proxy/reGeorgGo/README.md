**README**

### ⚠️声明(中文版本)

📢声明⚠️：本人及本项目与“IceCache”、“IcePeony”均毫无关系❗️❗️本人及本项目与“IceCache”、“IcePeony”均毫无关系❗️❗️本人及本项目与“IceCache”、IcePeony均毫无关系❗️❗️切勿将nao-sec 安全团队的分析文章中所提及的“IceCache”与本项目混为一谈。
1. **两个程序区别很大**：两个程序的功能丰富度、命令行参数也都不一样！本项目只是基于reGeorg的demo代码。
2. **reGeorgGo晚出现于“IceCache”**：“IceCache”在2023年09月06日编译，而sec_demo中的reGeorgGo在2023年12月28日才编写。也就是，在“IceCache”恶意程序出现三个月之后，才出现本项目中的reGeorgGo。
3. **项目名称是随机命名**：reGeorgGo的编写是出于对reGeorg的研究和安全检测学习，reGeorgGo名字是随便起的。不是含有字符串“reGeorgGo”就能说明是同一个程序！！IceCache恶意程序中的 "Main root" 字符串是`reGeorgGo`，本项目的名称只是碰巧和它相同，纯属巧合而已。甚至这个demo程序名称还可以命名为reGeorgNaoSec、reGeorg_nao_sec、reGeorg—Rintaro，亦或者是Rintaro Koike和Shota Nakajima。
4. **安全声明与故意留的检测特征**：为防止工具被黑客滥用，该项目从创建之初就被声明了严禁非法使用、仅用于研究和教学目的，且源码只有简单的功能，还保留了易于安全产品检测的特征字符串——`Georg says, 'All seems fine'`。
5. **停止传播误导性信息**: 虽然本项目与“IceCache”毫无关系，但还是感谢nao_sec安全团队如此费心地对一个小demo代码的错误宣传。这个demo代码在实战没什么用，望nao_sec安全团队停止传播误导性信息。
6. **再次声明**：本项目所发布的内容仅供学习和研究用途，严禁用于违法活动或商业盈利。若有违反，违反者将自行承担相应法律责任，违反者的行为与内容属主无关。请遵守相关法律法规，共同维护网络环境的清朗！



### ⚠️Declaration(English Version)

📢Declaration⚠️： **This project and the owner have no association with "IceCache" or ”IcePeony“. And we're unrelated❗️❗️** **This project and the owner have no association with "IceCache" or ”IcePeony“. And we're unrelated❗️❗️** **This project and the owner have no association with "IceCache" or ”IcePeony“. And we're unrelated❗️❗️** The "IceCache" mentioned in the analysis article by the nao-sec security team should not be conflated with this project. Below are detailed clarifications to avoid any misunderstanding:

1. **Program Differences**: The two programs exhibit significant differences in functionality, feature richness, and command-line parameters. This project is based solely on reGeorg's demo code and does not share any direct relationship with "IceCache."  
2. **Different development time sequence**: The "IceCache" program was compiled on September 6, 2023, whereas reGeorgGo within this project was developed on December 28, 2023. Thus, reGeorgGo appeared three months after "IceCache," further emphasizing its independence.  The nao-sec article uses very vague rhetoric and logic to explain that IceCache references reGeorgGo's code. Past code can reference future packages? How does the IceCache file compiled on September 06, 2023 refer to the demo source code on December 28, 2023?
3. **Randomness of the project name**: The name "reGeorgGo" was chosen arbitrarily for this project, which is based on research and security detection of reGeorg. The coincidence of the name with the string "reGeorgGo" found in the IceCache malware is purely accidental. Even the demo program could have been named reGeorgNaoSec, reGeorg_nao_sec, Regeorg-rintaro, or Rintaro Koike and Shota Nakajima without altering its functionality.  
4. **Security Measures and Intentional Detection Features**: In order to prevent the tool from being abused by hackers, the project has been stated from the beginning that illegal use is strictly prohibited and only used for research and teaching purposes. The source code includes only basic functionalities and retains the detectable feature string 'Georg says, "All seems fine"' to facilitate identification by security products.  
5. **Cease the dissemination of misleading information**: Although this project is in no way associated with "IceCache," we would like to extend our gratitude to the nao_sec security team for their deliberate attempts at defamation, which have inadvertently increased awareness of this fairly minor tool. Bravo!
6. **Reaffirm**: The code published in this repository is only for study and research purposes, and is strictly prohibited for illegal activities or commercial profits. If there is a violation, the violator will bear the corresponding legal responsibilities, and the violator’s behavior has nothing to do with the content owner. Please abide by relevant laws and regulations and jointly maintain a clear network environment!


-------------------------
# Useage


```bash
Usage: ./reGeorgGo [OPTIONS]
./reGeorgGo [-l addr] [-p port] [-u http tunnel url]

Example:
./reGeorgGo -l 127.0.0.1 -p 1080 -u http://192.168.1.5:8000/tunnel.nosocket.php
    
Options:
  -l string
        The default listening address (default "127.0.0.1")
  -p string
        The default listening port (default "1080")
  -u string
        The url containing the tunnel script
```


# Educational and Research Use Only

This repository is intended for educational and research purposes. It is not to be used for any illegal activities. Users are solely responsible for their actions, and the author of this repository shall not be held liable for any misuse.

Before you proceed, please take note of the following usage guidelines:

1. **Educational and Research Purposes Only:** This repository is exclusively for educational and research purposes. It is not intended for any form of illegal or unethical activities. Using the content here for such purposes is strictly prohibited.

2. **User Responsibility:** Users are entirely responsible for their actions and the way they use the materials provided in this repository. Any consequences arising from misuse will be the sole responsibility of the user.

3. **No Author Liability:** The author(s) of this repository will not be held accountable for any misuse, legal issues, or damages that may result from the usage of the materials or code provided.


