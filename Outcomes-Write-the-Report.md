# Outcomes write the report. Decisions shape the craft.

Some nights the incident isn’t in the SIEM, it’s in my head.

I’ll be halfway through a trivial task, and my brain just pops up with: “Hey, remember that incident where you completely missed the obvious thing? Let’s replay that. In ridiculous detail. Again, and again.”

If you’ve been doing cyber for a while, you probably know that feeling. One missed IOC, one rushed choice, and you move back into that mental neighbourhood of:

>I should’ve seen that. I could’ve done more. Why didn’t I connect those dots?

It’s not a fun place. But it does start to feel normal, which is its own problem.

---

## The neat little story I used to believe

For a long time I had a very simple way of grading incidents in my head.

If the incident was contained quickly, then we made good decisions. If it blew out, then somebody messed up.

Nice logic. Looks tidy on a slide. Fits under a heading like “Lessons Learned” if you need to pretend everything is simple.

Real incidents kept ruining that story.

I’ve when teams do everything reasonably right. They built a solid hypothesis, pulled the right logs, checked the obvious blind spots, and still got smashed because of some weird quirk in the environment that nobody knew about. No playbook for it. No way they could have known in that moment.

I’ve also watched corners cut, skipped checks, jumped straight to conclusions on a feeling, and absolutely nothing went wrong that time. Everyone moved on, and the risky reasoning never got talked about because the outcome was fine.

Then there are the reviews where the final result looks bad, but when you wind back to the actual decision point and look only at what they knew then, it’s very hard to honestly say you’d have picked a different path.

At some point it finally landed for me, not in a dramatic way, more like a slow annoying realization:

>The outcome is not the scorecard. The quality of the decision, at the moment you make it, is.

Not the retro you write afterwards. Not the “obviously we should have” version that shows up once you’ve got full logs, timeline, and two weeks of hindsight.

---

## More fog than clean puzzle

From the outside, people sometimes imagine cyber security as a neat little puzzle. Collect all the data, apply the method, get the right answer.

Most of the time it feels more like working in fog.

Half the telemetry is missing because it was never turned on. The bits you do have are noisy, inconsistent, or tied to hostnames that got reused three times. Artifacts don’t collect cleanly on exactly the systems you care about. And meanwhile people are asking you for a yes/no answer because they’ve got their own decisions to make.

We still have to act.

Contain or keep watching. Block the account now or wait for one more piece of proof. Escalate with a “likely compromise” call when the data is fuzzy, or hold off and risk being late.

And the uncomfortable truth is: you can make a solid decision in that fog and still end up with a painful outcome. You can make a lazy decision and walk away looking like a genius because this time nothing else was going on.

Outcome and decision quality are connected, but they’re not the same thing. If your culture only reacts to the outcome, the whole team slowly drifts into weird habits.

---

## The fear no one writes into the playbook

I’ve seen good analysts freeze up, not because they don’t know the next technical step, but because they’re scared of being the one who “got it wrong”.

So you start seeing patterns like:

They keep doing “just one more check” before they’re willing to say what they think. They document every tiny detail like they’re building a legal defence, not an incident timeline. They hide behind the tooling: “the platform says X,” instead of, “based on this data, I think X is most likely.”

On the other end you get the “lucky hero” thing.

Someone makes fast, loose decisions a few incidents in a row, the outcomes happen to be fine, and suddenly the story becomes “they’re brilliant under pressure.” Nobody looks closely at the actual reasoning, because the dashboard is green and people are tired and just want a win.

Both of these are bad patterns.

One slowly kills confidence and slows the whole response. The other normalises gambling with other people’s risk.

---

## What changes when you care about decision quality

The teams that feel sane, tend to talk about incidents a bit differently.

After an incident, they don’t jump straight to “who broke this” or “who saved us”.

They ask things like, “Given what we knew at the time, was this a good decision?”

That one question changes the tone straight away.

Suddenly it’s normal for people to say:

“Here’s what I saw and what I thought it meant, and here’s the bit I wasn’t sure about.” “Here’s the assumption I was relying on.” “Here’s the guess I made but didn’t say out loud during the call.”

You also get more honest statements such as:

“We got a good outcome here, but that was mostly luck. The reasoning doesn’t survive another roll of the dice.” “We got hammered on this, but your call made sense at the time. The gaps in visibility were the real problem.”

That’s not being soft on people. It’s just actually useful. You learn something you can carry forward, instead of just handing out blame or praise based purely on how the graph ended up looking.

---

## How I try to handle it now

None of this is a proper framework. It’s just what I try to lean on when my brain wants to replay old incidents for the hundredth time.

When something goes well, I try to ask myself, “If we reran that ten times with the same approach, would I still be comfortable?” If the honest answer is “probably not,” then, fine, we were lucky. Good to know. Don’t pretend it was master-level decision making.

When I’m giving feedback, I try to get people to walk me through their thinking, not just the final step. What did you see first, what did you rule out, what did you assume without writing it down. That’s where the interesting stuff usually lives.

And when I’m making a call on thin data, I try to say that out loud. Something like, “This is a 60/40 call. We don’t have time to wait for perfect evidence. Here’s what I’m choosing and why.” It’s not pretty, but at least it’s honest about the uncertainty that was actually there.

Do I still replay old incidents in my head? Of course. That hasn’t magically gone away. The tape still runs, usually when I’m trying to sleep.

The question I try to use now, though, isn’t “how did I not see that,” as if I was supposed to be omniscient. It’s closer to:

Given what I knew then, was my decision solid enough? And what would I change about my process next time, not just the ending I wish I’d gotten?

Sometimes the honest answer is “no, that was not a good call,” and it stings a bit. But that’s the bit that’s actually useful.

---

### The part that sticks
If cyber has a moral, maybe it’s this:

>Outcomes write the report. Decisions shape the craft.

If cyber has a moral, maybe it’s this:

>Outcomes write the report. Decisions shape the craft.
