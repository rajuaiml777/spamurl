"""NSFW Phishing URL"""
import re
import pickle
import validators
from feature import FeatureExtraction
class SpamPredictor:
    """SpamPredictor class for predicting spam URLs."""
    def __init__(self):
        self.urls_pattern = r'(?:(?:(?:ftp|http)[s]*:\/\/|www\.)[^\.]+\.[^ \n]+)'
        self.invalid_prefixes = ["ww.", "http://ww.", "https://ww.", "http://w.", "https://w.", "htps://www."]
        self.a_domain = set()
        self.b_w_list = set()
        self.op_domains = set()
        with open("op_model.sav", "rb") as model_file:
                    op_domains22 = pickle.load(model_file)
        self.op_domains.update(op_domain11.strip().lower() for op_domain11 in op_domains22)
        with open("model_domain.sav", "rb") as model_file:
                    op_domains2 = pickle.load(model_file)
        self.a_domain.update(op_domain1.strip().lower() for op_domain1 in op_domains2)             
        with open("model_lexical_b.sav", "rb") as model_file:
                    op_domains22 = pickle.load(model_file)
        self.b_w_list.update(op_domain4.strip().lower() for op_domain4 in op_domains22)
        with open('model_gbc_spam_ham_05122023.sav', 'rb') as file:
            self.loaded_model = pickle.load(file)
        self.obj = FeatureExtraction()
    async def sample(self,inputurl_url):
        self.basic_validation = True
        for b_word in self.b_w_list:
            if b_word in inputurl_url:
                self.url_results.append({"url": inputurl_url,"status": "spam"})
                self.basic_validation = False
                return
        for op_domain in self.op_domains:
            if op_domain in inputurl_url:
                self.url_results.append({"url": inputurl_url,"status": "ham"})
                self.basic_validation = False
                return
        for ad_domain in self.a_domain:
            if ad_domain in inputurl_url:
                self.url_results.append({"url": inputurl_url,"status": "spam"})
                self.basic_validation = False
                return
    async def is_valid_url(self,input_url):
        """validurl' if the URL is valid, 'invalidurl' otherwise."""
        return 'invalidurl' if any(input_url.startswith(prefix) for prefix in self.invalid_prefixes)  else 'validurl'
    async def get_results_from_model(self, input_text_url):
        """The classification result indicating whether the text is 'ham' or 'spam', or 'undetermined' if the feature list length is not 76."""
        get_feature_list=await self.obj.getFeaturesList(input_text_url) 
        if len(get_feature_list)!=76:
            try:
                status_code2 = self.obj.response.status_code
            except:
                result_url= 'spam'
                return result_url            
            if status_code2 in (100, 101, 201, 202, 203, 204, 205, 206, 999):
                result_url= 'ham'
                return result_url
            elif status_code2 in (300, 301, 302, 303, 304, 305, 307, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 500, 501, 502, 503, 504, 505):
                result_url= 'spam'
                return result_url
            else:
                result_url= 'spam'
            return  result_url
        pred_cls = self.loaded_model.predict([get_feature_list])
        if pred_cls[0]==0:
            result_url= 'ham'
        else:
            result_url= 'spam'
        return result_url
    async def get_predictions(self, input_url):
        """Retrieves predictions for a list of input URLs."""
        final_prediction = {}
        self.url_results = []
        if len(input_url) == 0 or input_url == [] or input_url == [" "] or input_url == [""]:
            final_prediction["reason"] = "no input URL provided"
            final_prediction["spam_url"] = None
            final_prediction["final_output"] = None
        else:
            for inputurl_url in input_url:
                if inputurl_url.startswith("www."):
                    inputurl_url = "https://" + inputurl_url
                inputurl_url = (inputurl_url.strip()).lower()
                text_ext = re.sub(self.urls_pattern, '', inputurl_url)
                if len(text_ext)>0:
                    self.url_results.append(
                        {"url": inputurl_url,
                        "status": "invalid url format."})
                else:             
                    await self.sample(inputurl_url)
                    if self.basic_validation == True:
                        url_check = await self.is_valid_url(inputurl_url)
                        if url_check == 'validurl':                    
                            output = await self.get_results_from_model(inputurl_url.lower())
                            if output == "spam":
                                self.url_results.append(
                                    {"url": inputurl_url,
                                    "status": "spam"})
                            elif output == "ham":
                                self.url_results.append(
                                    {"url": inputurl_url,
                                    "status": "ham"})
                        else:
                            self.url_results.append(
                                {"url": inputurl_url,
                                "status": "invalid url format."})                          
            final_output_list = [result["status"] for result in self.url_results]
            if "spam" in final_output_list:
                final_output = "spam"
                reason = "The URL is not safe for work"
            elif "invalid url format." in final_output_list:
                final_output = "invalid url format."
                reason = "invalid url format."
            else:
                final_output = "ham"
                reason = "The URL is safe for work"
            final_prediction["urls"] = self.url_results
            final_prediction["spam_url"] = final_output
            final_prediction["reason"] = reason
            return final_prediction
