#include <iostream>

struct User {
    int id;
    char* name;
};

void process_user_request(int user_id, bool clear_data) {
    User* user_data = new User();
    user_data->id = user_id;
    user_data->name = new char[10];
    
    if (clear_data) {
        delete[] user_data->name;
        delete user_data;
    }
    
    std::cout << "Processed request for user ID: " << user_data->id << std::endl;
}

