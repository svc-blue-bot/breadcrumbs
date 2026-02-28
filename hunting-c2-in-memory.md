---
layout: default
title: Hunting C2 Activity In Memory
---
[<Home](https://svc-blue-bot.github.io/breadcrumbs/)


# Hunting C2 Activity in Memory

## How to actually carve out what malware was talking to

One of the first things you want to understand in any intrusion is how the malware was communicating out of the network. The trouble is, a lot of modern tooling never writes its configuration or C2 details to disk. Some of it barely leaves logs behind. But memory… memory usually tells the truth, even if the rest of the system has been wiped clean or is a bit of a mess.

What makes memory so helpful is that it captures the system in the middle of doing whatever it was doing. If something was beaconing out, or holding decrypted config data, or even just preparing a request buffer, that stuff tends to remain in RAM long enough for you to dig it out. So if the disk looks “too clean”, you pivot to the memory dump.

This post walks through the spots in memory where C2 traces usually hide, and how you can carve them out without overcomplicating things.

---

## Why memory still gives you the real story

When a malware implant runs, it has to decrypt itself, load whatever libraries it wants, build its HTTP or TCP buffers, do DNS lookups, generate URIs, whatever. All of that takes place in RAM, not on disk. Even implants that encrypt their config on disk have to decrypt it in memory before they can talk to their server. And the best part is that Windows is not very quick to scrub memory: you often find half-finished sockets, leftover buffers, registry data, and other oddities that would never survive on disk.

For example, let’s say the malware contacted a domain and then wiped its traces. The memory image might still have the domain in a resolver cache fragment, or in a temporary buffer inside wininet. Same goes for IPs, HTTP headers, user agents, encryption keys. They float around long after the process itself has ended.

That’s why memory is often your last and best chance at recovering how the malware talked back home.

---

## Where the C2 clues actually sit in RAM

The first and easiest area is network structures. Tools like Volatility’s netscan do a good job at pulling socket objects out of RAM, including ones that closed just before you grabbed the dump. You might see a remote IP and port that has no matching process left, which is already interesting.

Then you’ve got the process memory regions. If a process has injected code, or something reflectively loaded, you usually find it in a VAD region with weird permissions like RWX or no file backing. These areas often contain the malware’s internal state. That means C2 URLs, GUIDs, encryption keys, beacon settings… basically the guts of the implant.

There are also the temporary buffers created by user-mode networking libraries. Each HTTP request, or decrypted response, or staging request, exists in memory for a moment. Malware doesn’t obfuscate these at runtime unless it is really fancy. So if you carve around the buffers inside processes calling winhttp or wininet, you sometimes find entire beacon messages.

And somewhere in RAM, usually scattered in different places, you’ll find partial DNS lookups. Even a half-constructed FQDN can be enough to identify a C2 domain.

---

## A practical workflow for finding the C2 trail with Volatility

You start by finding what looks suspicious in the process list. pslist and pstree are fine for this. Anything with a strange parent chain or that shouldn’t be networking gets a closer look. psscan is useful because hidden processes sometimes show up here even if they don't appear in the normal lists.

Once you pick a few candidate processes, run netstat and netscan. netstat shows the live stuff, netscan shows the leftovers. If you see remote IPs that make you raise an eyebrow, keep those aside.

The next phase is digging into the process’s memory layout with vadinfo. You are trying to spot memory regions that feel "off": pages that are private, executable, or just unusually large compared to what a normal process would allocate. malfind helps a lot here, because it not only highlights suspicious regions but also dumps them. These dumps are where you usually find the C2 goodies.

Now comes the carving. Strings is still underrated for C2 hunting. Even a simple scan across VAD dumps often reveals URLs, HTTP verbs, user agents, internal IDs, encryption keys and more. If you know what malware families you suspect, a few YARA rules can go a long way. And if the malware reflectively loaded a DLL, carving for PE headers often recovers the entire payload, including config data inside it.

Some implants encode their configs using XOR or base64. You can usually guess the encoding from the structure of the data. Light decoding is sometimes all you need to reveal the raw C2 domains and URIs.

---

## A quick example: Cobalt Strike in memory

Cobalt Strike is a nice example because it leaves a very predictable configuration block in memory once it runs. It includes the public key, sleep times, jitter values, user agent, and of course, the C2 address. Even though the beacon config is encrypted on disk, the decrypted form is always in memory when active.

Dumping the right VAD region almost always gives you this block. From there you can map out exactly what profile the operator was using and what servers they were calling out to.

---

## DNS and resolver fragments are the forgotten heroes

Even if the main C2 indicators aren’t obvious at first, the DNS fragments in memory can save you. Malware that performs lookups (even once) tends to leave pieces of those domains scattered across memory structures. They might be incomplete, but still recognizable. This gives you something to pivot on when direct sockets are missing.

---

## Turning raw indicators into something meaningful

Once you pull out a domain or IP address, the real work starts. You correlate it with the suspicious process’s VAD layout, its command line, its handles, and any strange memory regions. That helps determine whether it was a legitimate process reaching out somewhere weird, or injected malware controlling it.

You then compare the recovered indicators to anything known from intelligence sources or past incidents. Simple user agent strings or characteristic URI patterns can often link an intrusion to a specific toolset. You also check whether the infrastructure is active, whether it is shared across multiple victims, or whether this was a one-off staging host.

All of this comes together to build a picture of what the attacker was doing, how they controlled the compromised machine, and how far they could go.

---

## Wrapping up

Carving C2 data out of memory is not a complicated art, but it does require patience. You look for strange processes, strange network activity, strange memory regions. You dump them, carve them and slowly piece together the C2 channel. Memory gives you the most honest view of what was happening on the system, even when attackers try to hide or clean up after themselves.

Most importantly, once you recover how the malware was communicating, you can cut it off, identify other infected hosts, and understand the operator’s intent. And more often than not, the entire conversation between attacker and implant is sitting right there in RAM, waiting for someone to take the time to pull it apart.
