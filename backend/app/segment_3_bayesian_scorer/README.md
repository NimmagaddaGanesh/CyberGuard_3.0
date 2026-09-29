# Segment 3: Bayesian Confidence Scorer & Context Synthesizer
> **Owner:** Bayesian Context Lead / AI Engineer

## Responsibilities
This segment is responsible for calculating quantitative confidence scores for resolutions using empirical historical performance and vector semantic similarity.

### Formula Implemented:
$$ \text{Confidence} = (w_{\text{semantic}} \times \text{VectorSimilarity}) + \left(w_{\text{empirical}} \times \frac{\text{Successes} + 1}{\text{Trials} + 2}\right) $$

* **Laplace Smoothing:** $\frac{\text{Successes} + 1}{\text{Trials} + 2}$ prevents overfitting on low sample sizes.
* **Weights:** $w_{\text{semantic}} = 0.40$, $w_{\text{empirical}} = 0.60$.

### Files:
* `bayesian_scorer.py`: Computes confidence scores, ranks actions, and formats the augmented context bundle for the LLM Copilot (Segment 4).
