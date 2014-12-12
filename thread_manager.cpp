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

std::vector<ProducedHashPair> foundPasswords;
std::mutex foundPasswordsMtx;
std::atomic<uint64_t> n {0};
bool run = true;

const std::array<SingleWordFunctor, 3> SINGLE_WORD_FUNCTORS 
{
  [](const DictionaryVec& vec, const DictionaryIterator& it, const uint64_t& round)
  {
    if (round == 0) {
      return std::make_pair(*it, Hash(*it));
    } else {
      std::string str = *it;
      str.append(std::to_string(round-1));
      return std::make_pair(str, Hash(str));
    }
  },
  [](const DictionaryVec& vec, const DictionaryIterator& it, const uint64_t& round)
  {
    std::string str = *it;
    str[0] = std::toupper(str[0]);
    if (round > 0) {
      str.append(std::to_string(round-1));
    }
    return std::make_pair(str, Hash(str));
  },
  [](const DictionaryVec& vec, const DictionaryIterator& it, const uint64_t& round)
  {
    std::string str = *it;
    toUpper(str);
    if (round > 0) {
      str.append(std::to_string(round-1));
    }
    return std::make_pair(str, Hash(str));
  }
};

void producerThreadMain(const DictionaryIterator begin, const DictionaryIterator end, const PasswordMap& passwordHashes)
{
  uint64_t round = 0;

  while (true) {
    auto it = begin;
    
    while (it < end) {
      for (const auto& getPasswordHashPair : SINGLE_WORD_FUNCTORS) {
	auto newProduct = getPasswordHashPair(dictionary, it, round);
	if (passwordHashes.find(newProduct.second) != passwordHashes.end()) {
	  std::lock_guard<std::mutex> lock(foundPasswordsMtx);
	  foundPasswords.emplace_back(std::move(newProduct));
	}
      }
      if (!run) {
	n.fetch_add(end-it);
	return;
      }
      ++it;
    }
    n.fetch_add(dictionary.size());
    ++round;
  }
}

void consumerThreadMain()
{
  static std::vector<ProducedHashPair> results;
  while(run) {

    {
      std::lock_guard<std::mutex> {foundPasswordsMtx};
      results = foundPasswords;
    }

    for (const auto& result : results) {
      
    }
  }
}

ThreadManager::ThreadManager(const PasswordMap& passwordHashes)
  : m_passwordHashes(passwordHashes)
{

}

ThreadManager::~ThreadManager()
{
  stopProducers();
  //m_consumer.join();
}

void ThreadManager::launchConsumer()
{
  m_consumer = std::thread(consumerThreadMain);
}

void ThreadManager::launchProducers()
{
  auto n = std::max(std::thread::hardware_concurrency(), 1u);
  uint64_t wordsPerThread = dictionary.size()/n;

  auto begin = dictionary.begin();
  auto end = dictionary.begin() + wordsPerThread;
  if (wordsPerThread > 0) {
    for (uint32_t i = 0; i < n-1; ++i) {
      m_producers.emplace_back(std::bind(producerThreadMain, begin, end, m_passwordHashes));
      begin += wordsPerThread;
      end += wordsPerThread;
    }
  }
  m_producers.emplace_back(std::bind(producerThreadMain, begin, dictionary.end(), m_passwordHashes));
}

void ThreadManager::stopProducers()
{
  run = false;
  for (auto& thread : m_producers) {
    thread.join();
  }
  m_producers.clear();
}

