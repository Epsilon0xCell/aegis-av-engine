# Disclaimer

Template notice: This document is a template drafted for a public educational project. It is not legal advice, it was not written by a lawyer, and it is not a substitute for advice from a qualified lawyer in your own jurisdiction. Review and adapt it with legal counsel before relying on it for a public release.

## What this project is

This repository contains defensive security simulators created by Epsilon0xCell for education and defensive research. It combines:

- A fake command and control simulator that runs on localhost only.
- A fake ransomware simulator that operates only inside a dedicated sandbox folder on dummy files created for the lab.

Both tools are simulation and teaching tools. They are designed to help students, defenders, and researchers understand how these classes of attack work in outline, so they can build, test, and improve detections and defences. They are intentionally limited: they include deliberate markers, local-only operation, allowlisted simulated actions, and recovery paths that real malicious software does not have.

## Educational and defensive purpose only

This project is provided for educational and defensive purposes only, including:

- Coursework and supervised lab study.
- Building and testing detection rules, logging, and alerting.
- Incident response training and tabletop or hands-on exercises in isolated lab environments.
- Defensive research conducted with authorization on systems you own or are expressly permitted to test.

No other purpose is authorized by the author.

## Authorized lab environments only

Use this software only in authorized lab environments, meaning environments that meet all of the following conditions:

- The computers, virtual machines, networks, and accounts involved belong to you, or you have clear, prior, written permission from the owner to use them for security testing.
- The environment is isolated from production systems, production data, and other people's systems and data.
- No real personal, customer, employer, or third-party data is placed in the lab, except data you have a clear legal right and a clear need to use for defensive testing.

If you do not have that permission, do not run this software against or on that system or network.

## No authorization is granted by this repository

Downloading, copying, or reading this code does not give you permission to access, test, interrupt, encrypt, or otherwise affect any computer, account, network, or data that is not yours to test. Authorization can only come from the owner of the system in question. Neither the author nor this disclaimer can grant it.

## Laws may apply where you are

Many countries, states, and regions have laws that restrict unauthorized access to computers, interception of communications, interference with systems or data, and the creation or distribution of certain kinds of harmful software. Examples in general terms include computer misuse and unauthorized access laws, wiretapping and interception laws, data protection and privacy laws, and export control rules that can apply to some security technology.

Laws differ widely by place, and they change over time. You are solely responsible for learning and following every law and regulation that applies to you, your location, your organization, and the systems and people your work could affect. If a use you are considering would be unlawful where you are, or where the affected system is, do not do it.

Nothing in this repository is a representation that any particular use is legal in any particular place.

## You assume all risk and legal responsibility

By downloading, copying, running, modifying, or redistributing this software, you accept that:

- You act entirely at your own risk.
- You are solely responsible for your own decisions, configurations, modifications, and actions, and for any consequences that follow from them.
- You are solely responsible for any legal, disciplinary, employment, academic, civil, or criminal consequences of your use or misuse.
- The author is not responsible for monitoring your use and cannot prevent misuse by others.

If you are unsure whether a planned use is lawful, authorized, or within your organization's policy, stop and obtain proper authorization and qualified advice before proceeding.

## No warranty

This software and documentation are provided "as is" and "as available", without any warranty of any kind, express or implied, to the fullest extent permitted by applicable law. Without limiting that statement, no warranty is given that:

- The software is safe, accurate, complete, current, or free of defects.
- The software will meet your needs, run without interruption, or work with your systems.
- The simulations in this project fully match the behaviour of any real attack, product, or malware family.
- Any detection, mitigation, or recovery method described here will prevent, detect, or reverse a real incident.

Security tools and simulations can fail, can behave unexpectedly in new environments, and can cause data loss, downtime, or other harm if misconfigured or misused. Keep backups that are separate from the lab, test recovery before you need it, and never rely on a lab simulator as your only defence.

## No affiliation or endorsement

This is an independent personal project by Epsilon0xCell. It is not affiliated with, endorsed by, sponsored by, or produced in cooperation with:

- Any employer, school, university, or training provider, unless a separate written statement says otherwise in this repository.
- The vendors, projects, or communities whose products, frameworks, or research are mentioned for comparison, teaching, or citation.
- The authors or operators of any real malware family, campaign, or service discussed for defensive purposes.

Names, product names, and framework names mentioned in teaching material belong to their respective owners and are used only to identify them for discussion and defence.

## Defensive information can still be incomplete or out of date

Attack techniques, vendor guidance, fixed software versions, detection logic, and legal requirements change quickly. Material in this repository reflects the knowledge and sources available at the time it was written and may be wrong, superseded, or incomplete. Verify important claims against primary sources, such as the relevant vendor advisory, the official vulnerability record, and current guidance from your own organization, before acting on them.

## Limitation of responsibility of the author

To the fullest extent permitted by applicable law, the author disclaims responsibility for damages or losses arising from use, inability to use, modification, or redistribution of this software, including direct, indirect, incidental, consequential, or punitive damages, and including loss of data, loss of revenue, interruption of service, or claims brought by third parties.

Nothing in this disclaimer is intended to exclude or limit any liability or right that cannot lawfully be excluded or limited in your jurisdiction. If part of this disclaimer is held unenforceable, the remaining parts continue to apply to the fullest extent permitted by law.

## Modifications and redistribution

If you modify this software, your modified version is your responsibility. Do not present a modified version as if it were the original, do not remove safety limits or warnings and then attribute the result to the original author, and do not use the author's name to imply endorsement of your version. If you redistribute this project or a version of it, include this disclaimer, the responsible use policy, and the licence that governs this repository, and make the lab-only and authorization limits at least as prominent as they are here.

## A disclaimer has limits

This disclaimer records the intended purpose of this project and the conditions the author asks users to follow. It does not, by itself, create legal immunity for the author or for any user, and it does not make an unlawful or unauthorized act lawful or authorized. Courts, regulators, employers, schools, and platform providers may apply their own rules regardless of what this file says.

## Questions

Questions about intended use of this project should be directed through the contact method listed in RESPONSIBLE_USE.md in this repository. That contact is for project questions and responsible disclosure. It is not a channel for requesting help with unauthorized activity, and requests of that kind will not be answered.

Last updated: Draft, not yet dated for public release. Add the release date when this file is published, and review it again at that time.
