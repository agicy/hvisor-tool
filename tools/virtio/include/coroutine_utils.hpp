// SPDX-License-Identifier: GPL-2.0-only
#ifndef COROUTINE_UTILS_HPP
#define COROUTINE_UTILS_HPP

#include "log.h"

#include <coroutine>
#include <exception>
#include <iostream>

namespace virtio {

struct Task {
    struct promise_type {
        Task get_return_object() { return Task{std::coroutine_handle<promise_type>::from_promise(*this)}; }
        std::suspend_never initial_suspend() { return {}; }
        std::suspend_never final_suspend() noexcept { return {}; }
        void return_void() {}
        void unhandled_exception() { std::terminate(); }
    };
    
    std::coroutine_handle<promise_type> handle;
    
    Task(std::coroutine_handle<promise_type> h) : handle(h) {}
    // Task(const Task&) = delete;
    // Task(Task&& t) : handle(t.handle) { t.handle = nullptr; }
    // ~Task() { if (handle) handle.destroy(); } 
    // For this simple case, we leak/detach easily.
};

struct CoroutineEvent {
    std::coroutine_handle<> waiter;
    bool signaled = false;

    // 1. 【防御核心】禁用拷贝构造和赋值操作
    CoroutineEvent(const CoroutineEvent&) = delete;
    CoroutineEvent& operator=(const CoroutineEvent&) = delete;
    CoroutineEvent() = default;

    // 2. 轻量级的代理 Awaiter 类
    // 编译器会把这个极小的对象拷贝到协程栈帧里，而它牢牢抓住了本体的引用
    struct Awaiter {
        CoroutineEvent& event; // 引用真正的本体对象！

        bool await_ready() { 
            if (event.signaled) { 
                event.signaled = false; 
                return true; 
            }
            return false; 
        }
        
        void await_suspend(std::coroutine_handle<> h) {
            event.waiter = h; // 句柄被稳稳地写进了真正的本体中！
        }
        
        void await_resume() {
            event.signaled = false;
        }
    };

    // 3. 重载 operator co_await
    // 当协程执行 co_await event 时，返回一个代理对象给编译器去折腾
    Awaiter operator co_await() {
        return Awaiter{*this};
    }

    bool await_ready() { 
        // If signaled, consume signal and continue
        if (signaled) { 
            signaled = false; 
            return true; 
        }
        return false; 
    }
    
    void await_suspend(std::coroutine_handle<> h) {
        waiter = h;
    }
    
    void await_resume() {
        // When resumed, we consumed the signal (or were resumed by IO loop if we integrated it there)
        // But here signal() resumes us directly.
        signaled = false;
    }
    
    void signal() {
        signaled = true;
        if (waiter) {
            auto h = waiter;
            waiter = nullptr;
            h.resume();
        }
    }
};

} // namespace virtio

#endif // COROUTINE_UTILS_HPP
