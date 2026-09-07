---
name: grilling
description: Grill the user relentlessly about a plan, decision, or idea. Use when the user wants to stress-test their thinking, or uses any 'grill' trigger phrases.
---

Interview me relentlessly about every aspect of this until we reach a shared understanding. Walk down each branch of the decision tree, resolving dependencies between decisions one-by-one. For each question, provide your recommended answer.

Interactive mode is the default: ask one question at a time, wait for feedback,
and use each answer to choose the next branch.

When the user explicitly requests a **batch grill**, traverse the same decision
tree internally and return one consolidated set of assumptions, recommended
answers, unresolved branches, and consequences. Do not silently use batch mode
for an ordinary grill request.

If a *fact* can be found by exploring the environment (filesystem, tools, etc.), look it up rather than asking me. The *decisions*, though, are mine — put each one to me and wait for my answer.

Do not act on it until I confirm we have reached a shared understanding.

Before acting, verify that every material branch is either answered, explicitly
deferred, or listed as unresolved, and that the user confirmed the resulting
decision set.
