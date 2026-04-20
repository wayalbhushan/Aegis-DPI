#ifndef AEGIS_THREAD_SAFE_QUEUE_H
#define AEGIS_THREAD_SAFE_QUEUE_H

#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>
#include <chrono>

namespace Aegis {

/**
 * @brief Thread-safe queue for high-performance packet passing between threads.
 * Uses std::mutex and std::condition_variable to signal without busy-waiting.
 *
 * @tparam T Type of items held in the queue.
 */
template<typename T>
class ThreadSafeQueue {
public:
    explicit ThreadSafeQueue(size_t max_size = 10000) : max_size_(max_size) {}
    
    /**
     * @brief Pushes an item into the queue. Blocks if the queue is full.
     */
    void push(T item) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_full_.wait(lock, [this] { return queue_.size() < max_size_ || shutdown_; });
        
        if (shutdown_) return;
        
        queue_.push(std::move(item));
        not_empty_.notify_one();
    }
    
    /**
     * @brief Tries to push an item without blocking.
     * @return true if successful, false if queue is full or shutting down.
     */
    bool tryPush(T item) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.size() >= max_size_ || shutdown_) {
            return false;
        }
        queue_.push(std::move(item));
        not_empty_.notify_one();
        return true;
    }
    
    /**
     * @brief Pops an item from the queue. Blocks if empty.
     */
    std::optional<T> pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        not_empty_.wait(lock, [this] { return !queue_.empty() || shutdown_; });
        
        if (queue_.empty()) return std::nullopt;
        
        T item = std::move(queue_.front());
        queue_.pop();
        not_full_.notify_one();
        return item;
    }
    
    /**
     * @brief Pops an item from the queue with a timeout.
     */
    std::optional<T> popWithTimeout(std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!not_empty_.wait_for(lock, timeout, [this] { return !queue_.empty() || shutdown_; })) {
            return std::nullopt;
        }
        
        if (queue_.empty()) return std::nullopt;
        
        T item = std::move(queue_.front());
        queue_.pop();
        not_full_.notify_one();
        return item;
    }
    
    /**
     * @brief Checks if the queue is empty.
     */
    bool empty() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }
    
    /**
     * @brief Returns the current number of elements in the queue.
     */
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }
    
    /**
     * @brief Signals queued threads to wake up and begins shutdown process.
     */
    void shutdown() {
        std::lock_guard<std::mutex> lock(mutex_);
        shutdown_ = true;
        not_empty_.notify_all();
        not_full_.notify_all();
    }
    
    /**
     * @brief Checks if the queue is shutting down.
     */
    bool isShutdown() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return shutdown_;
    }

private:
    std::queue<T> queue_;
    mutable std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    size_t max_size_;
    bool shutdown_ = false;
};

} // namespace Aegis

#endif // AEGIS_THREAD_SAFE_QUEUE_H
