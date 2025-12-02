# **Investigation Tips Worth Keeping Close**
Investigation Tips Worth Keeping Close is a list I originally wrote for myself, something I revisit and add to. I’m sharing it here because the same small habits that keep me grounded during messy investigations, while this isn't the full list this still may help someone else stay on track too.

---

## General Tips

**• Slow down during verification.**  
Tiny details—like an unfamiliar DNS chunk—can carry major implications if you rush past them.

**• Don’t just *see* artifacts observe them.**  
Treat every trace as a clue with context, relationships, and limitations.

**• Cycle through “how” and “why.”**  
Interrogate every action, dependency, and decision in the chain until the behavior makes sense.

**• Pivot to MITRE ATT&CK only when it adds clarity.**  
Use it to reinforce understanding, not replace it.

**• Let emotions be signals, not drivers.**  
Frustration, excitement, or urgency can hint at bias. Note them, don’t follow them.

**• Correlate across platforms every time.**  
Cross-signals from EDR, logs, network data, and system artifacts often reveal the real story.

**• Run multiple queries or approaches to validate a finding.**  
Different angles, same conclusion, helps catch false positives.

**• Challenge your own assumptions.**  
Ask questions designed to expose your blind spots before you commit to a conclusion.

**• Use careful wording - precision matters.**  
Write like your claims will be scrutinized in court.

**• Break complex investigations into manageable slices.**  
If the workload spikes, reduce the scope and tackle one piece at a time.

**• First verify whether the thing you’re searching for even exists.**  
Avoid confirmation bias, check presence before proof.

**• Keep an incident response checklist handy.**  
It prevents tunnel vision and ensures coverage of foundational steps.

**• Compare anything suspicious against baseline behavior.**  
Abnormality only matters when you know what “normal” looks like.

**• Start by identifying what the machine actually provides.**  
Know your available sources before diving deep.

**• Use the internet shamelessly.**  
If something is unknown, search it as speed matters.

**• When root cause stalls, pivot to related suspicious indicators.**  
A side pattern (e.g., RDP session activity) often leads back to the core issue.

**• Use a modified Pomodoro approach.**  
Limit time spent chasing a single IOC unless it’s producing meaningful returns.

**• Document as you investigate.**  
A live writeup solidifies learning and reduces backtracking later.

**• Use a hex editor when file type identification is unclear.**

**• Rephrase any AI-generated help in your own words.**  
This exposes misunderstandings and prevents shallow knowledge.

**• grep is your friend.**  
Simple text searching solves more problems than people admit.

**• Fully chase an IOC across all systems then move on.**  
Exhaust the thread, close it out, proceed.

**• Screenshot everything and keep your workspace organized.**

**• If you get stuck, move forward.**  
Later findings often unlock earlier confusion.

---

## Tips for BTLO
These tips are more so for online labs / challenges where everything is provided, and may be repeat some points from the above as it was originally intended to be seperate.

**• Start by scoping what you actually have.**  
Identify every available log or data source and get a feel for where visibility is strong, thin, or missing entirely. Logging coverage shapes what you _can_ and _cannot_ say later.

**• Establish a fast baseline of “normal.”**  
Skim for common patterns, regular activity, and expected noise. You don’t need perfection, just enough of a baseline so anomalies start to stand out instead of everything looking suspicious.

**• Hunt for quick wins and obvious indicators first.**  
Look for well-known tools, suspicious commands, bad keywords, or recurring patterns that pop early. These low-hanging signals help you orient faster and can give you anchor points for deeper analysis.

**• Capture leads without diving deep immediately.**  
Tag anything interesting, events, hosts, users, timestamps and loosely group them by category (e.g., auth, network, persistence). The goal is to collect threads, not fully unravel each one yet.

**• Once the picture is big enough, start forming hypotheses.**  
When you’ve got enough context, propose working explanations and test them against the data. Validate, refine, or discard them and gradually build a timeline and storyline grounded in what’s actually confirmed.
