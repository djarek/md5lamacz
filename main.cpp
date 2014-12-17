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

#include <vector>
#include <atomic>
#include <fstream>
#include <algorithm>
#include <set>
#include <iostream>

#include "hash.h"
#include "thread_manager.h"

void loadPasswords(PasswordMap& map, const std::string& fileName)
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

void loadDictionary(DictionaryVec& dictionary, const std::string& fileName)
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

extern std::atomic<uint64_t> n;

int main()
{
  PasswordMap passwordHashes;
  DictionaryVec dictionary;
  
  loadDictionary(dictionary, "slownik.txt");
  loadPasswords(passwordHashes, "baza.txt");

  ThreadManager threadManager {passwordHashes, dictionary};
  threadManager.launchProducers();
  threadManager.launchConsumer();

  std::string cmd;
  while(true) {
    std::cin >> cmd;
    if (cmd == "q") {
      break;
    } else if (cmd == "slownik") {
      threadManager.stopAllThreads();
      std::cin >> cmd;
      loadDictionary(dictionary, cmd);
    }
  }
  threadManager.stopProducers();
  std::cout << "zmielonych hashow: " << n.load() << std::endl;
  return 0;
}