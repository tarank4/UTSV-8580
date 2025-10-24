from transformers import AutoTokenizer, AutoModelForCausalLM
import transformers
import torch
import models.config as config
from utils.mylogger import MyLogger
import os
from models.llm import LLM
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "max_split_size_mb:256"

_model_name_map = {
    "mistral-7b-instruct": 'mistralai/Mistral-7B-Instruct-v0.2',
    "mixtral-8x7b-instruct": 'mistralai/Mixtral-8x7B-Instruct-v0.1',
    "mixtral-8x7b": 'mistralai/Mixtral-8x7B-v0.1',
    "mixtral-8x22b" : "mistralai/Mixtral-8x22B-Instruct-v0.1"
}

class MistralModel(LLM):
    def __init__(self, model_name, logger: MyLogger, **kwargs):
        super().__init__(model_name, logger, _model_name_map, **kwargs)
        self.terminators = [
            self.pipe.tokenizer.eos_token_id,
            #        self.pipe.tokenizer.convert_tokens_to_ids("<|eot_id|>")
        ]

    def predict(self, main_prompt, batch_size=0, no_progress_bar=False):
        def rename(d):
            newd = dict()
            newd["role"]="user"
            newd["content"]=d[0]['content'] + '\n'+ d[1]['content']
            #print(d)
            #print(newd)
            return [newd]
            
        if batch_size > 0:
            prompts = [self.pipe.tokenizer.apply_chat_template(rename(p), tokenize=False, add_generation_prompt=True) for p in main_prompt]
            #print(prompts[0])
            self.model_hyperparams['temperature']=0.01
            return self.predict_main(prompts, batch_size=batch_size, no_progress_bar=no_progress_bar)
        else:
            prompt = self.pipe.tokenizer.apply_chat_template(
            main_prompt, 
            tokenize=False, 
            add_generation_prompt=True
            )
            self.model_hyperparams['temperature']=0.01
            #print(prompt)
            return self.predict_main(prompt, no_progress_bar=no_progress_bar)


        # assuming 0 is system and 1 is user
        system_prompt = main_prompt[0]['content']
        user_prompt = main_prompt[1]['content']
        prompt = f"<s>[INST] \\n{system_prompt}\\n{user_prompt}[/INST]"
        l=len(self.tokenizer.tokenize(prompt))
        self.log("Prompt length:" +str(l))
        limit=16000 if self.kwargs.get("max_input_tokens", None) is None else self.kwargs["max_input_tokens"]
        if l > limit:
            return prompt, "Too long, skipping: "+str(l)
        # if 'dataflow' in self.kwargs['system_prompt_type']:
        #     print(">Setting max tokens to ", 1024)
        #     self.model_hyperparams['max_new_tokens']=1024
        return self.predict_main(prompt)

if __name__ == '__main__':
    system="You are a security researcher, expert in detecting vulnerabilities. Provide response in following format: 'vulnerability: <YES/NO> | vulnerability type: <CWE_ID> | lines of code: <VULNERABLE_LINES_OF_CODE>"
    from data.bigvul import BigVul
    from data.cvefixes import CVEFixes
    #bigvul = BigVul(os.path.join(config.config['DATA_DIR_PATH'] ,"MSR_20_Code_vulnerability_CSV_Dataset"), logger=None)
    cvefixes=CVEFixes("cvefixes-c-cpp-method", logger=None).df
    #id, row = bigvul.get_next()
    row=cvefixes.iloc[0]['code']
    print(row)
    mistral_model = MistralModel("mixtral-8x7b-instruct", logger=None, max_input_tokens=1024, flash=False, system_prompt_type='')
    print(">>>Running Mistral")
    print(">>>ID:", str(id))
    model_input = [{"role": "system", "content": system}, {"role": "user", "content": row}]
    print(mistral_model.predict(model_input))
