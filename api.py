"""Phishing url api"""
import logging
from os import cpu_count
from logging import Formatter
from logging.handlers import RotatingFileHandler
from uvicorn import run as uvicorn_run
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from app import SpamPredictor
import asyncio
from fastapi_cache import FastAPICache
from fastapi_cache.backends.redis import RedisBackend
from fastapi_cache.decorator import cache    
from fastapi_cache import *


obj = SpamPredictor()
LOG_FILE = 'spam_detection_api.log'
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = RotatingFileHandler(filename=LOG_FILE,backupCount=1, encoding='utf-8', delay=False,maxBytes=1024*1024*1024)
formatter = Formatter(fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
del LOG_FILE
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    from redis import asyncio as aioredis
    redis = aioredis.from_url("redis://127.0.0.1:6379", encoding="utf8", decode_responses=True,db=0,use_as_cache=True)
    FastAPICache.init(RedisBackend(redis), prefix="fastapi-cache")

@cache()
async def get_cache():
    return 1
       
@app.post('/predict/')
@cache()
async def predict_category(req: Request):
    """spam url prediction"""
    try:
        json_request = await req.json()      
    except Exception as err:
        logger.error('The input JSON format: %s', err)
        return {"reason":"invalid input json format.", "spam_url":None,"final_output":None}
    try:
        logger.info("json_request: %s", json_request)
        predictions = await Helper(url=json_request.get("url"))
    except Exception as err:
        logger.error('Error while prediction model is calling: %s', err)
        return {"reason":"error while prediction model is calling", "spam_url":None,"final_output":None}      
    del json_request
    logger.info("Predictions: %s", predictions)
    return predictions
 
async def Helper(**kwargs):
    await asyncio.sleep(0.00000000001)    
    res = await obj.get_predictions(kwargs["url"])
    return res
  
if __name__ == '__main__':
    uvicorn_run("api:app", host="0.0.0.0", reload = True, port=8080,  workers=(2 * cpu_count()) + 1)