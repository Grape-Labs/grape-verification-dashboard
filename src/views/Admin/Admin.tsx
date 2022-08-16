import * as React from 'react';
import {
    Typography,
    Box,
    Button,
    Grid,
    Paper,
    Step,
    Stepper,
    StepLabel,
 } from '@mui/material';

 const steps = [
    'Get GAN',
    'Associate Discord',
  ];

 export default function HorizontalLabelPositionBelowStepper() {
    const [activeStep, setActiveStep] = React.useState(0);
    const [completed, setCompleted] = React.useState<{
        [k: number]: boolean;
    }>({});

    const totalSteps = () => {
        return steps.length;
      };
    
    const completedSteps = () => {
        return Object.keys(completed).length;
    };

    const isLastStep = () => {
        return activeStep === totalSteps() - 1;
    };

    const allStepsCompleted = () => {
        return completedSteps() === totalSteps();
    };

    const handleBack = () => {
        setActiveStep((prevActiveStep) => prevActiveStep - 1);
      };
    
    const handleStep = (step: number) => () => {
        setActiveStep(step);
    };

    const handleNext = () => {
        const newActiveStep =
          isLastStep() && !allStepsCompleted()
            ? // It's the last step, but not all steps have been completed,
              // find the first step that has been completed
              steps.findIndex((step, i) => !(i in completed))
            : activeStep + 1;
        setActiveStep(newActiveStep);
      };
    
    const handleComplete = () => {
        const newCompleted = completed;
        newCompleted[activeStep] = true;
        setCompleted(newCompleted);
        handleNext();
    };

    const handleReset = () => {
        setActiveStep(0);
        setCompleted({});
    };

    return (
      <Box sx={{ width: '100%' }}>
        <Stepper activeStep={1} alternativeLabel>
          {steps.map((label,key) => (
            <Step key={label}>
              <StepLabel>{label}</StepLabel>
            </Step>
          ))}
        </Stepper>
        
        <div>
        {allStepsCompleted() ? (
          <React.Fragment>
            <Typography sx={{ mt: 2, mb: 1 }}>
              All steps completed - you&apos;re finished
            </Typography>
            <Box sx={{ display: 'flex', flexDirection: 'row', pt: 2 }}>
              <Box sx={{ flex: '1 1 auto' }} />
              <Button onClick={handleReset}>Reset</Button>
            </Box>
          </React.Fragment>
        ) : (
          <React.Fragment>
            
            {activeStep+1 === 1 &&
                <Typography sx={{ mt: 2, mb: 1 }}>
                    Step {activeStep + 1}<br/><br/>

                    Show/detect GAN balance with wallet connected<br/>

                    Get GAN Token with SOL<br/>
                    Get GAN Token with USDC
                </Typography>
            }
            
            {activeStep+1 === 2 &&
                <Typography sx={{ mt: 2, mb: 1 }}>
                    Step {activeStep + 1}<br/><br/>
                    Associate your discord
                </Typography>
            }
            
            
            <Box sx={{ display: 'flex', flexDirection: 'row', pt: 2 }}>
              <Button
                color="inherit"
                disabled={activeStep === 0}
                onClick={handleBack}
                sx={{ mr: 1 }}
              >
                Back
              </Button>
              <Box sx={{ flex: '1 1 auto' }} />
              <Button onClick={handleNext} sx={{ mr: 1 }}>
                Next
              </Button>
              {activeStep !== steps.length &&
                (completed[activeStep] ? (
                  <Typography variant="caption" sx={{ display: 'inline-block' }}>
                    Step {activeStep + 1} already completed
                  </Typography>
                ) : (
                  <Button onClick={handleComplete}>
                    {completedSteps() === totalSteps() - 1
                      ? 'Finish'
                      : 'Complete Step'}
                  </Button>
                ))}
            </Box>
          </React.Fragment>
        )}
      </div>

      </Box>
    );
  }

export function AdminView(props: any) {
    return (
        <>
            <Grid item xs={12} sx={{mt:4}}>
                <Paper className="grape-paper-background">
                    <HorizontalLabelPositionBelowStepper />
                </Paper>
            </Grid>

            <Grid item xs={12} sx={{mt:4}}>
                <Paper className="grape-paper-background">
                    <Grid 
                        className="grape-paper" 
                        container
                        spacing={0}
                        alignContent="center"
                        justifyContent="center"
                        direction="column"
                        >
                        <Grid item>
                            <Typography 
                            align="center"
                            variant="h5">
                                Server Verification Management coming soon...
                            </Typography>
                        </Grid>
                    </Grid>
                </Paper>
            </Grid>
        </>
    );
}