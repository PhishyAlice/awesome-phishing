# awesome-phishing

Collection of useful resources for red teamers, pentesters, security reseachers and anyone interested in technical and non-technical aspects of phishing and related topics.

Idea, concept and some resources from [Awesome Red Teaming](https://github.com/yeyintminthuhtut/Awesome-Red-Teaming/).

Feel free to contribute any resources that might help to improve this list.


## Table of contents

* [E-mail security](#-e-mail-security)

* [OSINT for phishers](#-osint-for-phishers)

* [Phishing infrastructure](#-phishing-infrastructure)

* [Payloads and filter evasion](#-payloads-and-filter-evasion)

* [Tools and frameworks](#-tools-and-frameworks)

* [Books and ebooks](#-books-and-ebooks)

* [Campaign write-ups](#-campaign-write-ups)

* [Phishing prevention and detection](#-phishing-prevention-and-detection)

* [Phishing-related scientific research](#-phishing-related-scientific-research)

* [Miscellaneous](#-miscellaneous)

## [↑](#table-of-contents) E-mail security

## [↑](#table-of-contents) OSINT for phishers
* [Kali tools list](https://tools.kali.org/tools-listing)
* [OSINT framework](https://osintframework.com/)

## [↑](#table-of-contents) Phishing infrastructure
* [Going phishing with terraform](https://bestestredteam.com/2019/03/22/going-phishing-with-terraform/)
* [Building resilient phishing campaign infrastructure](https://godlikesecurity.com/index.php/2017/12/14/building-resilient-phishing-campaigns/)
* [Red Team Infrastructure Wiki](https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki)
* [Complete guide creating and hosting phishing page for beginners](https://null-byte.wonderhowto.com/forum/complete-guide-creating-and-hosting-phishing-page-for-beginners-0187744/)
* [Automating gophish releases](https://jordan-wright.com/blog/post/2018-02-04-automating-gophish-releases/)
* [Mail Server Setup](https://blog.inspired-sec.com/archive/2017/02/14/Mail-Server-Setup.html)
* [Safe red team infrastructure](https://medium.com/@malcomvetter/safe-red-team-infrastructure-c5d6a0f13fac)
* [Automated red team infrastructure deployment with terraform - part 1](https://rastamouse.me/2017/08/automated-red-team-infrastructure-deployment-with-terraform---part-1/)
* [Automated red team infrastructure deployment with terraform - part 2](https://rastamouse.me/2017/09/automated-red-team-infrastructure-deployment-with-terraform---part-2/)
* [Infrastructure for ongoing red team operations](https://blog.cobaltstrike.com/2014/09/09/infrastructure-for-ongoing-red-team-operations/)

## [↑](#table-of-contents) Payloads and filter evasion
* [Luckystrike a database backed evil macro generator](https://www.shellntel.com/blog/2016/9/13/luckystrike-a-database-backed-evil-macro-generator)
* [Powershell empire stagers 1 phishing with an office macro and evading avs](https://fzuckerman.wordpress.com/2016/10/06/powershell-empire-stagers-1-phishing-with-an-office-macro-and-evading-avs)
* [Executing metasploit empire payloads from ms office documemt properties part 1 of 2](https://stealingthe.network/executing-metasploit-empire-payloads-from-ms-office-document-properties-part-1-of-2)
* [Executing metasploit empire payloads from ms office documemt properties part 2 of 2](https://stealingthe.network/executing-metasploit-empire-payloads-from-ms-office-document-properties-part-2-of-2)
* [Excel macros with powershell](https://4sysops.com/archives/excel-macros-with-powershell/)
* [Powerpoint and custom actions](https://phishme.com/powerpoint-and-custom-actions/)
* [Macroless malware that avoids detection with yara rule)](https://furoner.wordpress.com/2017/10/17/macroless-malware-that-avoids-detection-with-yara-rule/amp/)
* [Hacking into whatsapp series part 2 phishing](https://null-byte.wonderhowto.com/forum/hacking-into-whatsapp-series-part-2-phishing-0179508/)
* [Macro-less code exec in msword](https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/)
* [Multi-platform macro phishing payload](https://medium.com/@malcomvetter/multi-platform-macro-phishing-payloads-3b688e8eff68)

## [↑](#table-of-contents) Tools and frameworks
### OSINT tools
* [Whois](http://whois.domaintools.com/)
* [HaveIBeenPwnd](https://haveibeenpwned.com/)
* [Creepy](https://github.com/ilektrojohn/creepy)
* [Maltego](https://www.paterva.com/buy/maltego-clients/maltego-ce.php)
* [Shodan](https://www.shodan.io/)
* [Censys](https://censys.io/)
* [TheHarvester](https://github.com/laramies/theHarvester)
* [Recon-ng](https://github.com/lanmaster53/recon-ng)
* [TinEye](https://www.tineye.com/)
* [SearX](https://searx.me/)

### Phishing campaign tools
* [Social Engineering Toolkit](https://github.com/trustedsec/social-engineer-toolkit/)
* [King Phisher](https://github.com/securestate/king-phisher)
* [FiercePhish](https://github.com/Raikia/FiercePhish)
* [ReelPhish](https://github.com/fireeye/ReelPhish/)
* [Fishing Cat Server](https://github.com/fishing-cat/fishing-cat-server)
* [GoPhish](https://github.com/gophish/gophish)
* [LUCY](https://lucysecurity.com/)
* [CredSniper](https://github.com/ustayready/CredSniper)
* [PwnAuth](https://github.com/fireeye/PwnAuth)
* [sptoolkit](https://github.com/chris-short/sptoolkit)
* [SpearPhisher](https://github.com/kevthehermit/SpearPhisher)
* [Wifiphisher](https://wifiphisher.org/)
* [Ares](https://github.com/dutchcoders/ares)
* [Phishing-frenzy](https://github.com/pentestgeek/phishing-frenzy)
* [SPF](https://github.com/tatanus/SPF)
* [Phishing pretexts](https://github.com/L4bF0x/PhishingPretexts)
* [Mercure](https://github.com/atexio/mercure)
* [Metasploit](https://github.com/rapid7/metasploit-framework)
* [Cobalt strike](https://www.cobaltstrike.com/help-spear-phish)

### Payload tools
* [The Browser Exploitation Framework](https://github.com/beefproject/beef)
* [LuckyStrike](https://github.com/curi0usJack/luckystrike)
* [Shellter](https://www.shellterproject.com/)
* [msfvenom](https://www.offensive-security.com/metasploit-unleashed/msfvenom/)
* [The Backdoor Factory](https://github.com/secretsquirrel/the-backdoor-factory)
* [Veil framework](https://github.com/Veil-Framework/Veil)

## [↑](#table-of-contents) Books and ebooks
* [Phishing Dark Waters: The Offensive and Defensive Sides of Malicious Emails](https://www.amazon.com/Phishing-Dark-Waters-Offensive-Defensive/dp/1118958470)
* [Phishing for Phools: The Economics of Manipulation and Deception](https://press.princeton.edu/books/hardcover/9780691168319/phishing-for-phools)
* [Scam Me If You Can: Simple Strategies to Outsmart Today's Rip-off Artists](https://www.amazon.com/Scam-Me-You-Can-Strategies/dp/0525538968)
* [Phishing: Detection, Analysis And Prevention](https://www.amazon.com/dp/1090376928/)
* [Social Engineering: The Science of Human Hacking](https://www.amazon.com/Social-Engineering-Science-Human-Hacking/dp/111943338X)
* [Don't Step in the Trap: How to Recognize and Avoid Email Phishing Scams](https://www.amazon.com/Dont-Step-Trap-Recognize-Phishing-ebook/dp/B01DXI9X0I)
* [Asset Attack Vectors: Building Effective Vulnerability Management Strategies to Protect Organizations](https://www.amazon.com/Asset-Attack-Vectors-Vulnerability-Organizations/dp/1484236262)
* [Cyberpsychology: The Study of Individuals, Society and Digital Technologies](https://www.amazon.com/Cyberpsychology-Individuals-Technologies-Textbooks-Psychology/dp/0470975628)
* [Stealing Your Life: The Ultimate Identity Theft Prevention Plan](https://www.amazon.com/Stealing-Your-Life-Ultimate-Prevention/dp/0767925874)
* [Open Source Intelligence Techniques: Resources for Searching and Analyzing Online Information](https://www.amazon.com/Open-Source-Intelligence-Techniques-Information/dp/1530508908)
* [Swiped: How to Protect Yourself in a World Full of Scammers, Phishers, and Identity Thieves](https://www.amazon.com/Swiped-Yourself-Scammers-Phishers-Identity/dp/1610397207)
* [Spam Nation: The Inside Story of Organized Cybercrime - from Global Epidemic to Your Front Door](https://www.amazon.com/Spam-Nation-Organized-Cybercrime_from-Epidemic/dp/1501210424)

## [↑](#table-of-contents) Campaign write-ups
* [Tainted Leaks: Disinformation and Phishing With a Russian Nexus](https://citizenlab.ca/2017/05/tainted-leaks-disinformation-phish/)
* [Nile Phish: Large-Scale Phishing Campaign Targeting Egyptian Civil Society](https://citizenlab.ca/2017/02/nilephish-report/)
* [Exposing One of China’s Cyber Espionage Units](https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf)
* [Grizzly Steppe - Russian Malicious Cyber Activity](https://www.us-cert.gov/sites/default/files//JAR_16-20296A_GRIZZLY%20STEPPE-2016-1229.pdf)
* [Gmail Phishing Campaign Racking Up Victims](https://www.pindrop.com/blog/gmail-phishing-campaign-racking-up-victims/)
* [Spying on a Budget: Inside a Phishing Operation with Targets in the Tibetan Community](https://citizenlab.ca/2018/01/spying-on-a-budget-inside-a-phishing-operation-with-targets-in-the-tibetan-community/)
* [Reckless Redux: Senior Mexican Legislators and Politicians Targeted with NSO Spyware](https://citizenlab.ca/2017/06/more-mexican-nso-targets/)
* [Reckless Exploit: Mexican Journalists, Lawyers, and a Child Targeted with NSO Spyware](https://citizenlab.ca/2017/06/reckless-exploit-mexico-nso/)
* [Shifting Tactics: Tracking changes in years-long espionage campaign against Tibetans](https://citizenlab.ca/2016/03/shifting-tactics/)
* [Packrat: Seven Years of a South American Threat Actor](https://citizenlab.ca/2015/12/packrat-report/)
* [How millions of DSL modems were hacked in Brazil, to pay for Rio prostitutes](https://citizenlab.ca/2012/10/how-millions-of-dsl-modems-were-hacked-in-brazil-to-pay-for-rio-prostitutes/)
* [Cloned RFE/RL phishing website in Uzbekistan](https://citizenlab.ca/2012/02/11988/)
* [Chinese hackers steal Gmail passwords: Google](http://m.digitaljournal.com/article/307490)
* [The RSA Hack: How They Did It](https://bits.blogs.nytimes.com/2011/04/02/the-rsa-hack-how-they-did-it/)

## [↑](#table-of-contents) Phishing prevention and detection

## [↑](#table-of-contents) Phishing-related scientific research
* [Why Phishing Works](https://cloudfront.escholarship.org/dist/prd/content/qt9dd9v9vd/qt9dd9v9vd.pdf)
* [PhishEye: Live monitoring of sandboxed phishing kits](http://193.55.114.4/docs/ccs16_phisheye.pdf)
* [Phishnet: predictive blacklisting to detect phishing attacks](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.168.4540&rep=rep1&type=pdf)
* [The current state of phishing attacks](https://kilthub.cmu.edu/articles/The_Current_State_of_Phishing_Attacks/6470498/files/11899055.pdf)
* [Understanding User Behaviors When Phishing Attacks Occur](https://ieeexplore.ieee.org/abstract/document/8823468)
* [Weaponizing data science for social engineering: Automated E2E spear phishing on Twitter](https://www.co.tt/files/defcon24/Speaker%20Materials/DEFCON-24-Seymour-Tully-Weaponizing-Data-Science-For-Social-Engineering-WP.pdf)
* [Do security toolbars actually prevent phishing attacks?](http://cs.union.edu/~fernandc/srs200/readings/SecurityToolbars.pdf)
* [Large-scale automatic classification of phishing pages](https://ai.google/research/pubs/pub35580.pdf)
* [Social phishing](http://www.markus-jakobsson.com/papers/jakobsson-commacm07.pdf)
* [Phishing for phishing awareness](https://www.tandfonline.com/doi/abs/10.1080/0144929X.2011.632650)

## [↑](#table-of-contents) Miscellaneous
* [PhishTank](https://PhishTank.com)
* [PhishBank](https://phishbank.org/)
* [KnowBe4 info site](https://www.knowbe4.com/phishing)
* [VirusTotal](https://www.virustotal.com/gui/)
