"""
finetuning.py  (FIXED)
----------------------
FIX: max_length=1024 → 2048
  Vulnerability explanations with full context (CVSS, OWASP, remediation,
  exploit context, vendor advisories) regularly exceed 1024 tokens.
  Training with 1024 truncates outputs mid-sentence, teaching the model
  to produce incomplete responses. 2048 is the practical sweet spot for
  T4 GPU (16GB) with QLoRA + gradient checkpointing.

  Memory budget at 2048:
    - Model (4-bit): ~5GB
    - Activations (batch=1, grad_ckpt): ~4GB
    - Optimizer states (paged_adamw_8bit): ~3GB
    - Total: ~12GB → fits T4 with ~4GB headroom
"""

import torch
import os
from datasets import load_dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
)
from peft import LoraConfig, get_peft_model, TaskType
from trl import SFTTrainer, SFTConfig

# ── Config ─────────────────────────────────────────────────────────────────────
BASE_MODEL    = "mistralai/Mistral-7B-Instruct-v0.3"
DATASET_PATH  = "data/training_pairs.jsonl"
OUTPUT_DIR    = "./checkpoints/vuln-mistral-7b"
HF_REPO_NAME  = "adityajayashankar/vuln-mistral-7b"

# ── Prompt format ──────────────────────────────────────────────────────────────
PROMPT_TEMPLATE = (
    "### Instruction:\n{instruction}\n\n"
    "### Input:\n{input}\n\n"
    "### Response:\n{output}"
)


def format_example(example):
    return {"text": PROMPT_TEMPLATE.format(
        instruction=example.get("instruction", ""),
        input=example.get("input", ""),
        output=example.get("output", ""),
    )}


# ── Load model in 4-bit ────────────────────────────────────────────────────────
def load_model():
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_compute_dtype=torch.float16,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
    )
    model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL,
        quantization_config=bnb_config,
        device_map="auto",
        trust_remote_code=True,
    )
    model.config.use_cache = False  # required for gradient checkpointing

    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    tokenizer.pad_token    = tokenizer.eos_token
    tokenizer.padding_side = "right"

    return model, tokenizer


# ── LoRA config ────────────────────────────────────────────────────────────────
def get_lora_config():
    return LoraConfig(
        task_type      = TaskType.CAUSAL_LM,
        r              = 16,
        lora_alpha     = 32,
        lora_dropout   = 0.05,
        bias           = "none",
        target_modules = ["q_proj", "v_proj", "k_proj", "o_proj"],
    )


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    if not os.path.exists(DATASET_PATH):
        print(f"❌ Dataset not found at {DATASET_PATH}. Run build_dataset.py first.")
        return

    print(f"Loading base model: {BASE_MODEL}")
    model, tokenizer = load_model()

    lora_cfg = get_lora_config()
    model    = get_peft_model(model, lora_cfg)
    model.print_trainable_parameters()

    print(f"\nLoading dataset: {DATASET_PATH}")
    dataset = load_dataset("json", data_files=DATASET_PATH, split="train")
    dataset = dataset.map(format_example)
    dataset = dataset.train_test_split(test_size=0.05, seed=42)

    print(f"  Train: {len(dataset['train'])} examples")
    print(f"  Eval:  {len(dataset['test'])} examples")

    training_args = SFTConfig(
        output_dir                   = OUTPUT_DIR,
        num_train_epochs             = 3,
        per_device_train_batch_size  = 1,
        gradient_accumulation_steps  = 16,
        gradient_checkpointing       = True,
        optim                        = "paged_adamw_8bit",
        learning_rate                = 2e-4,
        lr_scheduler_type            = "cosine",
        warmup_steps                 = 100,
        fp16                         = True,
        logging_steps                = 50,
        logging_strategy             = "steps",
        eval_strategy                = "steps",
        eval_steps                   = 200,
        save_steps                   = 200,
        save_total_limit             = 3,
        load_best_model_at_end       = True,
        max_length                   = 2048,   # FIX: was 1024 — too short for full vuln context
        dataset_text_field           = "text",
        report_to                    = "none",
    )

    trainer = SFTTrainer(
        model            = model,
        args             = training_args,
        train_dataset    = dataset["train"],
        eval_dataset     = dataset["test"],
        processing_class = tokenizer,
    )

    print("\n🚀 Starting fine-tuning...")
    trainer.train()

    # ── Save and Merge ──────────────────────────────────────────────────────
    trainer.save_model(os.path.join(OUTPUT_DIR, "final"))
    print(f"\n✅ Model saved to {OUTPUT_DIR}/final")

    print("\nMerging LoRA weights into base model...")
    merged = model.merge_and_unload()
    merged.save_pretrained(os.path.join(OUTPUT_DIR, "merged"))
    tokenizer.save_pretrained(os.path.join(OUTPUT_DIR, "merged"))
    print(f"✅ Merged model saved to {OUTPUT_DIR}/merged")

    # ── Push to Hub ─────────────────────────────────────────────────────────
    print(f"\nPushing to HuggingFace Hub: {HF_REPO_NAME}")
    from huggingface_hub import login
    login()

    merged.push_to_hub(HF_REPO_NAME)
    tokenizer.push_to_hub(HF_REPO_NAME)
    print(f"🚀 Model live: https://huggingface.co/{HF_REPO_NAME}")

    from datasets import load_dataset as ld
    full_ds = ld("json", data_files="data/vuln_dataset.jsonl", split="train")
    full_ds.push_to_hub(f"{HF_REPO_NAME}-dataset")
    print(f"🚀 Dataset live: https://huggingface.co/datasets/{HF_REPO_NAME}-dataset")


if __name__ == "__main__":
    main()