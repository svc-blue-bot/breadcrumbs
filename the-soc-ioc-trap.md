[<Home](https://svc-blue-bot.github.io/breadcrumbs/)


# The SOC IOC Trap in Big Incidents (Like Ransomware)

SOC work trains you into a very specific kind of integrity. You see a thing. You don’t wave your hands. You don’t guess. You don’t let it sit there unexplained. You chase it until you can say what it is, how it got there, what else it touched, and whether it matters.

And most of the time that habit is a good thing. It keeps you honest. It stops you from writing “looks bad” as if that means anything. It forces you to confirm, not vibe.

But there’s a point where the habit flips from integrity into compulsion, and you don’t really notice it happening because it still feels like good work.

Then you end up in something like ransomware, and suddenly your favourite SOC instinct becomes a liability.

Not because IOC work is useless, but because the way SOC teaches you to treat IOCs is basically: finish the thread or you’re doing it wrong.

That’s fine when the “incident” is a single phishing execution and a bit of post-click noise. It’s a trap when the incident is a moving adversary with time pressure, incomplete telemetry, multiple hosts, multiple pivots, and people asking for answers that don’t exist yet.

## What the SOC version of “good” looks like

Most SOC analysts learn their craft inside a structure that rewards completion.

You have an alert. You investigate. You escalate or close. You write the story. You produce a neat result. You move on.

Even when you’re deep-diving, the emotional endpoint is still the same: you want to be able to say “this was the cause”, “this was the chain”, “these were the impacted systems”, “this is the IOC list”, and then you can put it down.

That shape has a hidden consequence: it trains your brain to treat IOCs like the centre of gravity. Like if you just chase the most suspicious indicator hard enough, the incident will eventually collapse into a clean narrative.

And that’s true often enough that it becomes a default belief. You don’t consciously say it, but you behave like it:

if I can just explain this IOC properly, the rest will make sense.

That thought is incredibly seductive during chaotic work, because it promises a path back to certainty. A single thread you can pull until the knot comes undone.

The problem is that in major incidents, the knot is not a knot. It’s a pile of tangled fishing line someone threw into a fan.

## Ransomware punishes “thread completion” 

Ransomware is usually not one story. It’s several stories overlapping.

You’ll find things that are obviously malicious and still not the thing you need to focus on first. You’ll find things that look low-grade and end up being the most important pivot you’ve seen all day. You’ll find old infections that have nothing to do with the current blast but still light up your threat brain like a Christmas tree.

And the environment helps, because environments are messy even before the threat actor arrives.

There are always weird scripts, ancient admin tooling, broken scheduled tasks, scanners using stale credentials, half-deployed agents, and the occasional “why does this server talk to that country every night at 2am” that has been true for three years but nobody remembers why.

So you get dropped into an active ransomware response and you do what you were trained to do: you find an IOC that feels meaningful and you go after it properly. You open every log source you can. You search every dataset. You try to locate patient zero. You hunt first seen. You expand the scope to every endpoint that ever touched the indicator.

And it feels like progress because you’re doing real work. You’re producing evidence. You’re building a defensible thread. You can point to timestamps. You can prove the indicator exists. You can show where it appears.

Then you look up and realise you’ve burned the exact resource you don’t have in ransomware: time.

The uncomfortable part is that you can do “excellent IOC work” and still be strategically wrong, because the thing you chose to finish might not be the thing that changes the next decision.

Ransomware doesn’t care whether your IOC story is complete. It cares whether you contained lateral movement, whether you cut off access paths that matter, whether you identified the accounts and footholds that let them keep moving, whether you understood what they had and what they were about to do next.

##The IOC is usually not the question you should be answering

In routine SOC work, it’s normal to ask: “what is this?, In ransomware, the more useful question is: “what does this change?”

Does it change containment? Does it change which systems are at risk? Does it change whether we think the attacker still has access? Does it change the credibility of the story we’re building?

Because in a real incident, you’re not doing investigation in a vacuum. You’re doing it while decisions are being made around you, often faster than you’d like, and often with less evidence than feels responsible.

You don’t get to complete every thread before the decision point arrives.

So if your process is “finish the IOC”, you will keep arriving late to the real choices, armed with beautiful detail about something that might not have mattered.

## What actually works feels less satisfying 

The thing that actually works in messy incidents is not depth-first perfection. It’s iteration.

You find a lead. You follow it until you’ve extracted what it can realistically give you. You stop when it stops paying you back. You form a working explanation. You test that explanation against other sources. You adjust. You circle again.

It’s annoying because it doesn’t give the same psychological closure as finishing a thread.

Finishing a thread feels like control. Iteration feels like admitting you don’t have control yet.

But if you watch good responders in big incidents, that’s what they’re doing. They’re not married to the first interesting artifact they see. They’re building a model, and they’re willing to move on when a path turns into diminishing returns.

And here’s where MITRE ATT&CK actually becomes useful in the way people pretend it already is.

Not as a “map everything to techniques for the report” exercise.

As a way to keep your brain oriented on the parts that move the incident forward.

If you’re spending hours proving an IOC and you still don’t have confidence around access, lateral movement, credential theft, persistence mechanisms, and current attacker position, you’re probably solving the wrong problem first.

Because the reality is: in ransomware, you’re not chasing artifacts, you’re chasing attacker capability and momentum.

Where can they move from here? What access do they have? What did they already set up to come back? What did they do that suggests staging for impact? Where is the next likely move?

An IOC can contribute to that. It can also be dead weight.

“But what if that IOC was the key?”
It might be. That’s the part that makes people cling to completion.

Leaving an IOC thread unfinished feels risky, because you can imagine the future post-incident review where someone asks why you didn’t chase it. And you can imagine yourself having to say, “I didn’t have time", which feels weak.

But the truth is that everything in a major incident is a trade. If you spend four hours finishing one IOC thread, you’re choosing not to spend those four hours elsewhere. That’s also a risk. It just feels quieter.

A better way to hold it in your head is: you don’t abandon the IOC. You change the way you chase it.

You take it in passes, and the first pass is not “exhaustive explanation.” The first pass is “what does this connect to?”.

Which hosts. Which users. Which time window. Which execution context. Which other signals corroborate it. Does it line up with confirmed attacker behaviour or is it just adjacent weirdness.

Then you move on and keep building the bigger picture.

Later, when you circle back, you’re not searching for the IOC in a vacuum anymore. You’re testing it against a stronger model.

Now you can ask better questions, the kind that actually separate causal from adjacent:

Does this show up only on systems that later exhibit lateral movement? Is it tied to the same credential material? Does it precede the first confirmed remote service usage or follow it? Does it correlate with the same admin session pattern or token usage? Does it show up on hosts that were never otherwise touched?

That’s when IOC work starts becoming lethal instead of time-consuming.

## The habit I’ve built

I still partly have the IOC-chasing brain. I don’t think you ever fully lose it if you came up in a SOC. There’s a part of you that wants to chase every string until it’s tied neatly to the end of the incident.

But now I try to hold a different rule closer:

Follow the trail until it stops changing the incident, then move. Not because you’re done, but because you’re not allowed to be done yet.

Circle back when your model is better. When you can ask sharper questions. When the IOC is being used to test a hypothesis instead of becoming the hypothesis.

And when you do have to pause a thread, say it out loud (even if it’s only to yourself): this is a trade, not a failure.

Because the goal in complex response isn’t finishing the investigation. It’s surviving the investigation without getting hypnotised by a thread that never actually mattered.

In the SOC, chasing the IOC to the end is often what makes you good.

In large and complex incidents like ransomware, it’s often what makes you slow.

And if there’s one thing ransomware doesn’t care about, it’s whether your work was pretty and complete.

It cares whether you were fast in the right direction.
