/*
 * Copyright (c) 2022, Shashank Verma <shashank.verma2002@gmail.com>(shank03)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 */

#ifndef TASK_POOL_HPP
#define TASK_POOL_HPP

namespace pool {

    template <typename T>
    struct Listener {
        virtual void onCall(T *) = 0;
    };

    template <typename L, typename P>
    class TaskPool {
    private:
        std::vector<std::queue<P *> *> *pool;
        std::vector<std::thread *>     *workers;

        size_t index, n;

    public:
        explicit TaskPool(size_t thread_count) {
            index   = 0;
            n       = thread_count;
            pool    = new std::vector<std::queue<P *> *>(n, nullptr);
            workers = new std::vector<std::thread *>(n, nullptr);
            for (size_t i = 0; i < n; i++) (*pool)[i] = new std::queue<P *>();
        }

        void push_task(P *p) {
            (*pool)[index % n]->push(p);
            index++;
        }

        void wait_for_tasks() {
            for (size_t i = 0; i < n; i++) {
                (*workers)[i] = new std::thread(
                        [](std::queue<P *> *q) -> void {
                            while (!q->empty()) {
                                (new L())->onCall(q->front());
                                q->pop();
                            }
                        },
                        (*pool)[i]);
            }
            for (auto &t : *workers) t->join();
        }
    };
}    // namespace pool

#endif    // TASK_POOL_HPP
