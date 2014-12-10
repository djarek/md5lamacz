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

#include "hash.h"
#include <vector>
#include <thread>
#include <array>
#include <mutex>
#include <atomic>
#include <fstream>
#include <chrono>
#include <algorithm>
#include <set>
#include <iostream>

typedef std::vector<std::string> DictionaryVec;
typedef DictionaryVec::const_iterator DictionaryIterator;

typedef std::vector<std::thread> ThreadVec;
typedef std::pair<std::string, Hash> ProducedHashPair;
typedef std::function<ProducedHashPair(const DictionaryVec& vec, const DictionaryIterator& it, const uint64_t& round)> SingleWordFunctor;

std::string& toUpper(std::string& str)
{
  for (auto& c : str) {
    c = std::toupper(c);
  }
  return str;
}
std::string& toLower(std::string& str)
{
  for (auto& c : str) {
    c = std::tolower(c);
  }
  return str;
}

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

DictionaryVec dictionary;

std::vector<ProducedHashPair> foundPasswords;
std::mutex foundPasswordsMtx;
std::atomic<bool> run {true};
std::atomic<uint64_t> n {0};
void threadMain(const DictionaryIterator begin, const DictionaryIterator end, const PasswordMap& passwordHashes)
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
      if (!run.load()) {
	n.fetch_add(end-it);
	return;
      }
      ++it;
    }
    n.fetch_add(dictionary.size());
    ++round;
  }
}


void launchProducerThreads(ThreadVec& producerThreads, const PasswordMap& passwordHashes)
{
  auto n = std::max(std::thread::hardware_concurrency(), 1u);
  uint64_t s = dictionary.size()/n;
  uint32_t i = 0;
  if (s > 0) {
    for (; i < n-1; ++i) {
      producerThreads.emplace_back(std::bind(threadMain, dictionary.begin()+s*i, dictionary.begin()+s*(i+1), passwordHashes));
    }
  }
  producerThreads.emplace_back(std::bind(threadMain, dictionary.begin()+s*i, dictionary.end(), passwordHashes));
  
}

void loadPasswords(const std::string& fileName, PasswordMap& map)
{
  std::ifstream inputFile(fileName);
  uint64_t id = 0;
  std::string email, passwordHash;

  inputFile >> id >> email >> passwordHash;
  while(inputFile.good()) {
    map.insert(std::make_pair(Hash::storeHash(passwordHash), std::move(email)));
    inputFile >> id >> email >> passwordHash;
  }
}

void loadDictionary(const std::string& fileName)
{
  dictionary.clear();
  std::ifstream inputFile(fileName);
  std::string word;
  std::set<std::string> passwordSet;

  inputFile >> word;
  toLower(word);
  while(inputFile.good()) {
    auto it = passwordSet.insert(word);
    if (it.second) {
      dictionary.emplace_back(std::move(word));
    }
    inputFile >> word;
    toLower(word);
  }
}

int main()
{
  ThreadVec producerThreads;
  PasswordMap map;

  loadDictionary("slownik.txt");
  loadPasswords("baza.txt", map);
  launchProducerThreads(producerThreads, map);

  std::this_thread::sleep_for(std::chrono::seconds(6));
  run.store(false);
  for (auto& thread : producerThreads) {
    thread.join();
  }
  std::lock_guard<std::mutex> lock(foundPasswordsMtx);
  for (const auto& foundPassword : foundPasswords) {
    auto range = map.equal_range(foundPassword.second);
    std::for_each(
      range.first,
      range.second,
      [&foundPassword](PasswordMap::value_type& x){ std::cout << foundPassword.first << " "<< x.second << std::endl;}
    );
    //std::cout << std::endl;
  }
  std::cout << "hashow/s: " << n.load()/6.0 << std::endl;
  return 0;
}