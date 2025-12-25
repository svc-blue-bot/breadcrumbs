# Corporate Script Kiddies

## When automation becomes conversational
Over the last year or two, it’s become normal to watch LLMs “merge” into the corporate environment without anyone really calling it a program of work when in reality it should be. It’s not just a new app someone trialled and forgot about. It’s a sidebar in tools people already live inside daily. It’s a "business-as-usual" button in a operational workflow. It’s a browser tab that never closes. It’s an integration that turns “I wish I didn’t have to do this manually” into “here’s a script” fast enough that nobody pauses to think about what just changed.

From a SOC and IR perspective, the most meaningful shift isn’t that more people are using AI. It’s that more non-technical users are now producing technical outcomes. They’re writing PowerShell, Bash, Python, KQL, Splunk SPL, Graph API calls, ad-hoc SQL, little one-off automation chains that touch identity, endpoints, mailboxes, cloud resources, shared drives, and ticketing systems. They’re doing it to solve operational pain, not to “become developers”.

That’s the bit worth paying attention to, because it changes the risk profile in a way that’s easy to miss if you only look at whether the task got done.

The script runs, the spreadsheet updates, the mailbox gets cleaned up, the report is generated, and everyone moves on. In the moment it looks like pure productivity. In the background you’ve created a new class of change in the environment: changes that are fast, hard to review, often undocumented, and sometimes performed by people who don’t have the experience to sanity-check the failure modes.

None of this is a moral judgement on the users, either. Most of the time it’s the opposite. They’re trying to be helpful, reduce toil, and keep things moving. The risk comes from how easy it now is to turn intent into execution.

## The friction we used to rely on
A lot of corporate security was never designed around “everyone can script”. It was designed around the reality that scripting was specialised, and that specialisation created friction. Not always good friction, but friction nonetheless.

If someone in Finance wanted to bulk-change permissions, they usually had to ask IT. If someone in Operations wanted to pull telemetry from endpoints, they had to ask the SOC or an engineer. If a team wanted to automate a workflow, it often went through a pipeline of “can you write this?”, “can you test it?”, “can you deploy it?”, and “can you support it when it breaks?”

That process was slow, but it had a side effect: it forced review, and it forced ownership. Someone technical had to put their name and habits on the thing. Even if it was a quick-and-dirty script, it usually came with at least a minimal sense of blast radius, rollback, and “please don’t run this directly in production without telling anyone”.

Now, the constraint has shifted. A lot of people can generate code, but they can’t reliably evaluate it. They can’t tell the difference between “this is correct” and “this is plausible”. They don’t have the scar tissue that makes you instinctively ask, “what happens when this hits a null value?”, “is this idempotent?”, “what does this do to permissions?”, “what if this runs twice?”, “where does it log?”, “how do I reverse it if it partially succeeds?”

LLMs are very good at producing scripts that look like the right shape. They can give you a confident, clean-looking chunk of code with comments, functions, and a nice output message at the end. That presentation is persuasive, especially to someone who’s never had to triage a production outage caused by a script that printed “success” while quietly failing halfway through.

## Why it’s working so well
It’s worth being honest about why this has exploded. The value is real.

There’s a massive layer of operational work in most organisations that sits in an awkward space: too repetitive and annoying for humans, too small and scattered to justify a proper engineering effort, and too urgent to wait for the one person who can automate it properly. LLMs drop straight into that gap.

People are using them to glue systems together, reconcile data, standardise reporting, clean up tickets, bulk-update users, email automation, and build small scripts that remove hours of manual work. In many cases, the organisation does get a net benefit, at least in the short term.

The problem is that the same features that make it valuable also make it risky:

It’s fast, so people skip the thinking that normally happens during slower work.

It’s accessible, so the set of people creating automation is much larger than the set of people trained to manage automation safely.

It’s confident, so the output can look “finished” even when it’s missing the hard parts.

That’s the combination that creates incident-shaped holes later.

## The risk isn’t “AI wrote bad code”
When this topic comes up, it often gets framed as “what if the model hallucinates?” That does happen, but it’s not the centre of gravity in a corporate environment.

The risk is that a script is executed inside a real environment, with real permissions, on real systems, by someone who is trying to be productive and isn’t thinking like an engineer or an incident responder.

From an operational security lens, there are a few recurring failure modes that matter more than whether the code is elegant.

1) Blast radius is determined by access, not intent. In IR, you get used to the uncomfortable truth that impact is often about who had the permissions, not who had the best intentions. LLM-assisted scripting leans into that. A user might only mean to disable one account, clean up one mailbox, or adjust one group membership, but the script the model produced might target a whole OU, a whole tenant scope, or “all users where X”. If the person running it has broad access, the environment doesn’t care what they meant.

2) The script becomes a change mechanism with no change control. A lot of these scripts bypass the normal organisational controls that exist for good reasons. There’s no peer review, no CAB, no code repository, no artefact retention, no test environment, and no standard logging. It’s just “paste, run, done.” That’s a perfectly normal workflow for someone trying to get through their day, and a very bad workflow for anything that touches identity, permissions, endpoints, or production services.

3) “It worked once” turns into “this is now how we do it”. This is the sneaky one. A script solves a pain point, so it gets reused. Then someone shares it in Teams. Then it becomes the unofficial standard. Six months later it breaks because an API changes, a module updates, a naming convention shifts, or the environment evolves. The person who originally ran it might have moved teams, or forgotten the details, or never really understood what it did in the first place. Now you’ve got operational dependency without ownership, and when it fails it tends to fail at the worst possible time.

4) The output is optimised for completion, not safety. Models tend to optimise toward “give the user something that runs.” That’s useful, but it’s not the same as “give the user something that is safe in an enterprise.” Safety lives in the boring bits: scope limiting, dry-run capability, guardrails around destructive actions, retries with backoff, proper error handling, audit logs, and explicit confirmation prompts for high-impact operations. If you don’t ask for those, you often don’t get them.

## Attackers adapt to whatever we normalise
There’s another angle that starts to show up once you assume LLM use is embedded.

Attackers pay attention to how organisations operate, and they exploit the shortcuts we normalise. If it becomes common that people will run scripts generated from conversational tooling, or trust code suggestions in-line while they work, then you should expect adversaries to try to shape the inputs that those tools see.

I’m not talking about some dramatic Hollywood scenario. It can be as mundane as untrusted text appearing in places employees treat as “safe context”: emails, ticket descriptions, pasted log snippets, documentation pages, or internal chat. If the habit becomes “paste the thing into the model and run what it gives you”, then the boundary between untrusted input and privileged action gets thinner.

From a SOC standpoint, that’s uncomfortable because it creates a pathway where malicious influence can ride in on business-as-usual text, and the resulting action can look like legitimate admin activity. Attribution gets messy fast when the answer to “why did you run that?” is “it seemed reasonable and the model said it would fix it.”

The neat story that keeps failing in practice
There’s a simple way people judge these automations: did it work?

If the script ran and the operational task is done, it’s treated as a win. If it broke something, it’s treated as a mistake.

That’s tidy logic, and it’s not completely wrong, but it falls apart in real environments for the same reason incident outcome-based thinking falls apart.

A lot of unsafe scripts don’t cause immediate pain. They widen access slightly. They disable a check to “get it working.” They miss a corner case that just hasn’t been hit yet. They generate noise that slowly degrades detection quality. They create a dependency no one realises is critical until the person who ran it leaves.

A good outcome doesn’t necessarily mean a good decision. Sometimes it means you got lucky and nothing else intersected with the risky part of what you just did.

If you’ve spent time in IR, you’ve probably seen the parallel: you can make a rushed call and still get a clean containment, and you can make a solid call and still get burned because the environment had a blind spot you didn’t know about. The same logic applies here. “It worked” is not the same as “it was safe to normalise.”

## The part I keep coming back to
LLMs didn’t invent risky operational behaviour. Corporate environments have always been full of shortcuts, workarounds, and “temporary” fixes that quietly become permanent. What LLMs have done is remove the effort barrier, and effort barriers were doing more risk management than we like to admit.

If you’re in security operations, you can treat this as a novelty and wait for the first incident that has “ChatGPT script” somewhere in the root cause notes. Or you can treat it like what it is: a real shift in how changes get made, and who now has the ability to make them.

The most useful mental model I’ve found is to stop asking whether the script worked and start asking whether the decision to run it, in that moment, was defensible given what the person knew and what the environment could tolerate. That framing naturally forces questions about scope, testing, permissions, logging, rollback, and data handling. It also makes it easier to build a culture where people can say, “I’m not sure about this part,” without feeling like they’ve failed, because uncertainty is normal when you’re acting in a live environment.

In the end, the risk isn’t that non-technical users are automating things. The risk is that automation is now happening at scale without the habits that keep automation safe, and without the visibility that lets you investigate cleanly when something goes sideways.

If we want the productivity benefits without the incident-shaped surprises, we have to treat LLM-assisted scripting as part of operations, not a clever personal hack. The work still needs craft, even if the code came out of a chat window.
