# Responsible Use Policy

Template notice: This document is a template drafted for a public educational project. It is not legal advice and it is not a substitute for advice from a qualified lawyer, or for your own organization's security policy. See DISCLAIMER.md in this repository for the full disclaimer.

This policy states the conditions under which the author intends this combined defensive lab to be used. If you cannot meet these conditions, do not use this software.

## What this project contains

- A fake command and control simulator that binds to localhost only, uses deliberate identifying markers, and issues only allowlisted simulated tasks.
- A fake ransomware simulator that operates only inside a dedicated sandbox folder, only on dummy files created for the lab, and that writes encrypted copies while leaving originals in place, with a working local restore path.

Both tools are simulators for defensive learning. Their safety limits are part of the design. Removing, weakening, or working around those limits is a prohibited use of this project, described below.

## Acceptable use

You may use this project only for the following purposes, and only in an authorized, isolated lab environment as described in this policy:

1. Education and coursework: learning how beaconing, tasking, patch state checking, file encryption, and ransomware behaviour patterns work at a conceptual level.
2. Detection engineering: building, testing, and tuning detection rules, log pipelines, alerts, and dashboards against the known ground truth logs the simulators produce.
3. Defensive exercises: incident response training, purple team exercises, and recovery drills, where every participant has agreed to take part and the exercise is supervised or documented.
4. Defensive research on your own systems: checking your own lab machines for exposure, configuration, and recovery readiness.
5. Recovery practice: rehearsing restore and hash verification so that a real incident is not the first time the procedure is attempted.

## Prohibited uses

Do not use this project, any part of it, or any modified version of it, to do any of the following:

1. Access, test, scan, interrupt, damage, encrypt, or control any computer, account, network, or data without clear prior authorization from its owner.
2. Deploy, test, or rehearse an attack against a production system, a production network, an employer's or school's live systems, or any third party, whether or not you believe the test would be harmless.
3. Remove or weaken the safety limits built into these simulators. That includes, without limitation:
   - Changing localhost-only or sandbox-only operation so a tool can target other machines, folders, or file types.
   - Removing file markers, size limits, file count limits, or allowlists that restrict what a simulator may touch.
   - Removing or hiding the deliberate identifying markers, log records, banners, or fake notices that make these simulators recognizable as simulators.
   - Removing the local recovery path or the local retention of keys in the ransomware simulator.
   - Adding real command execution, real payload delivery, credential access, data theft, persistence, spreading, backup or snapshot destruction, security tool disabling, or log deletion features.
4. Use this project to develop, improve, test, package, or distribute real malware, real ransomware, real command and control infrastructure, or any tool intended to harm, extort, defraud, or gain unauthorized access.
5. Introduce real personal data, customer data, employer data, credentials, private keys, session tokens, or other sensitive material into the lab, or send lab traffic to real external services for testing.
6. Present these simulators, their output, or a modified version as a real incident, a real product, or a real threat, in order to deceive, extort, alarm, or gain an advantage over any person or organization.
7. Use this project in any way that breaks applicable law, your organization's policy, your school's policy, or a platform's terms of service.

If a use is not listed as acceptable above, treat it as not authorized by this policy until you have clear authorization and, where relevant, qualified advice.

## Lab isolation requirements

Before running either simulator, set up the lab as follows. These requirements apply to the combined lab as a whole, not only to exercises you consider risky.

### Isolation

- Run the lab inside a dedicated virtual machine that you can snapshot and discard. Do not run it on a daily use host, a work machine, or a family or shared computer.
- Use a host-only or otherwise isolated virtual network for the lab virtual machine. The fake command and control components are localhost only: keep them that way, and do not port forward, bridge, tunnel, or otherwise expose lab services to a home network, a campus network, a workplace network, or the internet.
- Give the lab virtual machine no access to production networks, production cloud accounts, or real credentials. If the lab does not need internet access for a given exercise, turn that access off for the exercise.

### Data

- Use only dummy data created for the lab. In the ransomware simulator, that means only files created by the lab's own dummy file generator, inside the sandbox folder, carrying the lab marker.
- Use no production data, no copies of production data, and no real documents, photos, mail, or databases, even if you believe they are safely backed up.
- Keep backups for recovery practice separate from the lab virtual machine, and test restoring from them as part of the exercise, not after it.

### Operation

- Snapshot the virtual machine before a run and roll back or discard it after the run.
- Run one simulator exercise at a time, read its ground truth log, and record what your detections did and did not catch before starting the next exercise.
- Stop the lab servers when an exercise ends. Do not leave lab services running unattended.
- Keep the lab's keys, tokens, and logs inside the lab. Do not publish them, and review any log before sharing it for teaching, because logs can contain hostnames, usernames, paths, and network details. See PUBLIC_RELEASE_CHECKLIST.md if a version of this material is ever prepared for public release.
- Tell anyone who shares a network, a classroom, or a workspace with you what the lab is, if there is any chance they could see its traffic, files, or notes and mistake them for a real incident.

### People

- Do not run exercises on, against, or in view of other people without their informed agreement.
- In a classroom or team setting, the instructor or exercise lead is responsible for confirming that every participant's lab meets the isolation and data requirements above.

## If something goes wrong

If a simulator behaves unexpectedly, affects files outside its sandbox, contacts a network you did not intend, or appears to have been mistaken for a real incident:

1. Stop the simulator and its server, and disconnect the lab virtual machine from any network.
2. Do not delete logs or artifacts. Preserve them for analysis.
3. Restore from your snapshot or from your separate backup.
4. If other people, systems, or organizations may have been affected, notify the relevant owner, instructor, or security team promptly and honestly, and follow their instructions and any applicable law.

## Responsible disclosure

This project is a defensive simulator, not a service, and it does not process other people's systems. Responsible disclosure here therefore covers two situations:

- You find a safety defect in this project itself, for example a way for the sandbox or localhost limits to be bypassed as shipped, a secret or private material mistakenly included in the repository, or a default that could cause harm.
- You find that material from this project is being publicly misused or misrepresented in a way the author should know about.

Contact placeholder: [Add a dedicated project contact before public release. Use a project email address or a GitHub private vulnerability report or security advisory contact for the repository. Do not list a personal email address, a home address, or a phone number here.]

When you report, please include:

- A short description of the issue and which file or version is affected.
- Steps to reproduce the safety issue inside an isolated lab, if it can be reproduced safely there.
- The impact you believe it has, stated plainly and without exaggeration.
- Whether the issue is already public anywhere.

Please do not include real credentials, other people's personal data, or material from systems you were not authorized to test.

Handling expectations, stated plainly as a template and to be confirmed before release:

- Reports sent in good faith about this project's own safety limits will be read and, where the report is accurate, corrected in a later version or the affected material will be withdrawn.
- This is a personal educational project, maintained as time allows. No response time, fix time, bounty, reward, or acknowledgement is promised.
- Do not test a suspected safety bypass against any system other than your own isolated lab while waiting for a response.
- Coordination request: if the issue could cause harm if published immediately, please give the author a reasonable chance to correct or withdraw the affected material before publishing details. No fixed embargo period is stated in this template, because the author should set one deliberately, with advice, before public release.

## Scope of this policy

This policy describes the author's intent and the conditions of use the author asks for. It does not grant any legal permission, it does not transfer any legal responsibility from a user to the author, and it does not make a prohibited act permitted because a user has read it. See DISCLAIMER.md.

Last updated: Draft, not yet dated for public release. Add the release date when this file is published, and review it again at that time.
