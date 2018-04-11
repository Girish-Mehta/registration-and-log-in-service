package com.offershopper.registrationandloginservice;

import org.springframework.data.mongodb.repository.MongoRepository;

public interface LoginProxyRepo extends MongoRepository<LoginInfo, String>{

}
