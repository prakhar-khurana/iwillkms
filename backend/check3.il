
LD      HMI_Start_Cycle     // Load the start button status
ANDN    System_Fault        // AND NOT fault active
JMPC    START_SEQ           // Jump if start is pressed
LD      Current_State
EQ      0                   // If state is 0 (Idle)
ST      Idle_Lamp           // Turn on Idle light
JMP     END_PROGRAM         // End cycle if not starting

START_SEQ:
LD      Part_Present
JMPNC   NO_PART_FAULT       // Jump if no part is present to fault state

// State 0: Idle / Homing Sequence
LD      Current_State
EQ      0
JMPC    STATE_10            // If state is 0, jump to state 10 (start homing)

// State 10: Move to Home Position (X-Axis)
STATE_10:
LD      Current_State
EQ      10
JMPC    MOVE_HOME_X
JMP     STATE_20

MOVE_HOME_X:
LDN     Home_X              // Load NOT Home_X sensor
ST      Motor_X_Reverse     // Move X towards home
LD      Home_X
JMPC    SET_STATE_20        // If at home, go to next state
JMP     END_PROGRAM

SET_STATE_20:
LD      20
ST      Current_State

// State 20: Move to Home Position (Y-Axis)
STATE_20:
LD      Current_State
EQ      20
JMPC    MOVE_HOME_Y
JMP     STATE_30

MOVE_HOME_Y:
LDN     Home_Y              // Load NOT Home_Y sensor
ST      Motor_Y_Reverse     // Move Y towards home
LD      Home_Y
JMPC    SET_STATE_30        // If at home, go to next state
JMP     END_PROGRAM

SET_STATE_30:
LD      30
ST      Current_State

// State 30: Move to Start Corner (Position 0,0)
STATE_30:
LD      Current_State
EQ      30
JMPC    MOVE_TO_START
JMP     STATE_40

MOVE_TO_START:
LD      0
ST      Target_X_Pos
ST      Target_Y_Pos
// (Assume a separate motion block handles moving to Target positions)
// For this example, we'll just set the state
LD      40
ST      Current_State

// State 40: Lower Cutter
STATE_40:
LD      Current_State
EQ      40
JMPC    LOWER_CUTTER
JMP     STATE_50

LOWER_CUTTER:
ST      Cutter_Down_Solenoid // Lower the cutting tool
LD      50
ST      Current_State

// State 50: Cut along X-axis to position 4
STATE_50:
LD      Current_State
EQ      50
JMPC    CUT_X1
JMP     STATE_60

CUT_X1:
LD      4                   // Target X position is 4
ST      Target_X_Pos
// Here we have a potential issue: using HMI value directly
LD      HMI_Cut_Speed       // Load speed from HMI
ST      Motor_X_Speed       // Set motor speed
LD      Current_X_Pos
GE      Target_X_Pos        // Check if X position is Greater or Equal to target
JMPC    SET_STATE_60
JMP     END_PROGRAM

SET_STATE_60:
LD      60
ST      Current_State

// State 60: Cut along Y-axis to position 4
STATE_60:
LD      Current_State
EQ      60
JMPC    CUT_Y1
JMP     STATE_70

CUT_Y1:
LD      4                   // Target Y position is 4
ST      Target_Y_Pos
LD      HMI_Cut_Speed
ST      Motor_Y_Speed
LD      Current_Y_Pos
GE      Target_Y_Pos
JMPC    SET_STATE_70
JMP     END_PROGRAM

SET_STATE_70:
LD      70
ST      Current_State

// State 70: Cut along X-axis back to position 0
STATE_70:
LD      Current_State
EQ      70
JMPC    CUT_X2
JMP     STATE_80

CUT_X2:
LD      0                   // Target X position is 0
ST      Target_X_Pos
LD      HMI_Cut_Speed
ST      Motor_X_Speed
LD      Current_X_Pos
LE      Target_X_Pos        // Check if X position is Less or Equal to target
JMPC    SET_STATE_80
JMP     END_PROGRAM

SET_STATE_80:
LD      80
ST      Current_State

// State 80: Cut along Y-axis back to position 0
STATE_80:
LD      Current_State
EQ      80
JMPC    CUT_Y2
JMP     STATE_90

CUT_Y2:
LD      0                   // Target Y position is 0
ST      Target_Y_Pos
LD      HMI_Cut_Speed
ST      Motor_Y_Speed
LD      Current_Y_Pos
LE      Target_Y_Pos
JMPC    SET_STATE_90
JMP     END_PROGRAM

SET_STATE_90:
LD      90
ST      Current_State

// State 90: Raise Cutter and complete cycle
STATE_90:
LD      Current_State
EQ      90
JMPC    RAISE_CUTTER
JMP     END_PROGRAM

RAISE_CUTTER:
LDN     Cutter_Down_Solenoid // De-energize solenoid to raise cutter
ST      Cutter_Down_Solenoid
// Another potential issue: unguarded division
LD      Total_Parts
ADD     1
ST      Total_Parts
LD      Cycle_Time_Total
ADD     OB1_PREV_CYCLE
ST      Cycle_Time_Total
LD      Cycle_Time_Total
DIV     Total_Parts         // Calculate average cycle time
ST      HMI_Avg_Cycle_Time
LD      0                   // Reset state machine to Idle
ST      Current_State

// Fault Handling
NO_PART_FAULT:
LD      TRUE
ST      No_Part_Fault_Alarm

END_PROGRAM:
// End of scan