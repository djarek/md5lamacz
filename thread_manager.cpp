/* Copyright 2014 Damian Jarek
    This file is part of md5lamacz.

    md5lamacz is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    md5lamacz is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with md5lamacz.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "thread_manager.h"
#include <atomic>
#include <mutex>
#include <iostream>
#include <algorithm>
#include <condition_variable>

std::vector<ProducedHashPair> foundPasswords;
std::mutex foundPasswordsMtx;
std::condition_variable cv;

std::atomic<uint64_t> n {0};
const uint32_t FLUSH_BUFFER_SIZE = 10;
const uint32_t NOTIFY_SIZE = 20;
bool run = true;

typedef std::function<ProducedHashPair(const DictionaryIterator& it, const uint64_t& round)> SingleWordFunctor;
typedef std::function<ProducedHashPair(const DictionaryIterator& it, const DictionaryIterator& it2, const uint64_t& round)> DoubleWordFunctor;

const std::array<SingleWordFunctor, 3> SINGLE_WORD_FUNCTORS 
{
  [](const DictionaryIterator& it, const uint64_t& round)
  {
    if (round == 0) {
      return std::make_pair(*it, Hash(*it));
    } else {
      std::string str = *it;
      str.append(std::to_string(round-1));
      return std::make_pair(str, Hash(str));
    }
  },
  [](const DictionaryIterator& it, const uint64_t& round)
  {
    std::string str = *it;
    str[0] = std::toupper(str[0]);
    if (round > 0) {
      str.append(std::to_string(round-1));
    }
    return std::make_pair(str, Hash(str));
  },
  [](const DictionaryIterator& it, const uint64_t& round)
  {
    std::string str = *it;
    toUpper(str);
    if (round > 0) {
      str.append(std::to_string(round-1));
    }
    return std::make_pair(str, Hash(str));
  }
};
const char characters[] = {'!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', ':', '"', ';', '\'', '\\', '[', ']', '{', '}', ',', '.', '/', '?', '`', '~', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
const auto DOUBLE_WORD_ROUND_LIM = sizeof(characters);

const std::array<DoubleWordFunctor, 3> DOUBLE_WORD_FUNCTORS
{
  [](const DictionaryIterator& it, const DictionaryIterator& it2, const uint64_t& round)
  {
    auto str = *it + *it2 + std::to_string(round);
    return std::make_pair(str, Hash(str));
  },
  [](const DictionaryIterator& it, const DictionaryIterator& it2, const uint64_t& round)
  {
    auto str = *it + characters[round % sizeof(characters)] + *it2;
    return std::make_pair(str, Hash(str));
  },
  [](const DictionaryIterator& it, const DictionaryIterator& it2, const uint64_t& round)
  {
    auto str = *it + *it2 + characters[round % sizeof(characters)];
    return std::make_pair(str, Hash(str));
  },
};

void producerThreadMain(const DictionaryVec& dictionary, const DictionaryIterator begin, const DictionaryIterator end, const PasswordMap& passwordHashes)
{
  uint64_t round = 0;
  std::vector<ProducedHashPair> buffer;
  buffer.reserve(SINGLE_WORD_FUNCTORS.size() + DOUBLE_WORD_FUNCTORS.size());

  while (true) {
    auto it = begin;
    auto it2 = dictionary.begin();
    
    while (it < end) {
      for (const auto& getPasswordHashPair : SINGLE_WORD_FUNCTORS) {
	auto newProduct = getPasswordHashPair(it, round);
	if (passwordHashes.find(newProduct.second) != passwordHashes.end()) {
	  buffer.emplace_back(std::move(newProduct));
	}
      }
      if (round <= DOUBLE_WORD_ROUND_LIM) {
	for (const auto& getPasswordHashPair : DOUBLE_WORD_FUNCTORS) {
	  auto newProduct = getPasswordHashPair(it, it2, round);
	  if (passwordHashes.find(newProduct.second) != passwordHashes.end()) {
	    buffer.emplace_back(std::move(newProduct));
	  }
	}
      }
      //Sekcja krytyczna
      //Jesli w buforze danego watku producenta uzbiera sie odp. liczba el.
      //to flushujemy zawartosc do wektora znalezionych hasel
      if (buffer.size() > FLUSH_BUFFER_SIZE) {
	std::unique_lock<std::mutex> lock {foundPasswordsMtx};
	for(auto& newProduct : buffer) {
	  foundPasswords.emplace_back(std::move(newProduct));
	}
	buffer.clear();
	if (foundPasswords.size() > NOTIFY_SIZE) {
	    lock.unlock();
	    cv.notify_one();
	}
      }
      if (!run) {
	n.fetch_add(end-it);
	return;
      }
      ++it;
      if (++it2 == dictionary.end()) {
	it2 = dictionary.begin();
      }
    }
    n.fetch_add(dictionary.size());
    ++round;
  }
}

void consumerThreadMain(const PasswordMap& passwordHashes)
{
  std::vector<ProducedHashPair> results;
  uint32_t foundPasswordsNumber = 0;
  uint32_t foundUserAccounts = 0;
  while (run) {
    { 
      //Sekcja krytyczna - zamieniamy miejscami wektory foundPasswords i results po tym jak
      //konsument zostaje obudzony dzieki czemu nie realokujemy pamieci,
      //a jedynie wykonujemy zamiane 2*3 slow maszynowych
      std::unique_lock<std::mutex> lock {foundPasswordsMtx};
      cv.wait(lock);
      std::swap(foundPasswords, results);
    }

    for (const auto& foundPassword : results) {
      auto range = passwordHashes.equal_range(foundPassword.second);
      ++foundPasswordsNumber;
      std::for_each(
	range.first,
	range.second,
	[&foundPassword, &foundUserAccounts](const PasswordMap::value_type& x) {
	    std::cout << foundPassword.first << " " << x.second << std::endl;
	    ++foundUserAccounts;
	}
      );
      std::cout << "---------------------------------------------------------" << std::endl;
    }
    results.clear();
  }
  std::cout << "Znaleziono haseł: " << foundPasswordsNumber << ", kont: "  << foundUserAccounts << std::endl;
}

ThreadManager::ThreadManager(const PasswordMap& passwordHashes, const DictionaryVec& dictionary)
  : m_passwordHashes(passwordHashes)
  , m_dictionary(dictionary)
{

}

ThreadManager::~ThreadManager()
{
  stopAllThreads();
}

void ThreadManager::launchConsumer()
{
  m_consumer = std::thread(std::bind(consumerThreadMain, m_passwordHashes));
}

void ThreadManager::launchProducers()
{
  auto n = std::max(std::thread::hardware_concurrency(), 1u);
  uint64_t wordsPerThread = m_dictionary.size()/n;

  auto begin = m_dictionary.begin();
  auto end = m_dictionary.begin() + wordsPerThread;
  if (wordsPerThread > 0) {
    for (uint32_t i = 0; i < n-1; ++i) {
      m_producers.emplace_back(std::bind(producerThreadMain, m_dictionary, begin, end, m_passwordHashes));
      begin += wordsPerThread;
      end += wordsPerThread;
    }
  }
  m_producers.emplace_back(std::bind(producerThreadMain, m_dictionary, begin, m_dictionary.end(), m_passwordHashes));
}

void ThreadManager::stopProducers()
{
  run = false;
  for (auto& thread : m_producers) {
    thread.join();
  }
  m_producers.clear();
}

void ThreadManager::stopAllThreads()
{
  stopProducers();
  cv.notify_one();
  m_consumer.join();
}